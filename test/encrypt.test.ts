import { beforeAll, describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { EncryptedFile } from '../src/encrypted/EncryptedFile';
import { DirID } from '../src/types';
import { DecryptionError, DecryptionTarget } from '../src/Errors';
import crypto from 'node:crypto';
import { TargetFS } from './TargetFS';
import { EncryptedDir } from '../src/encrypted/EncryptedDir';

async function randomBuffer(size: number): Promise<Uint8Array>{
	const arr = new Uint8Array(size);
	for(let i = 0; i < size; i++) arr[i] = Math.floor(Math.random() * 256);
	return arr;
}

describe('Test creating a vault', () => {
	const provider = new LocalStorageProvider();
	const dir = path.resolve(__dirname, 'encryptionTest');
	beforeAll(async () => {
		const testVaults = await provider.listItems(dir);
		for(const v of testVaults) await provider.removeDir(v.fullName);
	});
	test('Try creating a vault', async () => {
		await Vault.create(provider, dir, '12341234', {
			name: 'encTest1'
		});
		await expect(Vault.open(provider, path.resolve(dir, 'encTest1'), '1234123', null)).rejects.toThrowError(DecryptionError<DecryptionTarget.Vault>);
		await expect(Vault.open(provider, path.resolve(dir, 'encTest1'), '12341234', null)).resolves.not.toThrowError();
	});
	test('Try adding a file in root', async () => {
		const v = await Vault.create(provider, dir, '12341234', {
			name: 'encTest2'
		});
		const testFunction = async () => {
			const limit = 20;
			const buffers: Uint8Array[] = [];
			const hashes: Uint8Array[] = [];
			for(let i = 0; i < limit; i++) {
				const b = await randomBuffer(Math.pow(2, i));
				buffers.push(b);
				hashes.push(crypto.createHash('sha256').update(b).digest());
				await EncryptedFile.encrypt(v, `TestFile${i}.bin`, '' as DirID, b);
			}
			const items = await v.listItems('' as DirID);
			for(let i = 0; i < limit; i++){
				const item = items.find(it => it.decryptedName === `TestFile${i}.bin`);
				if(!item || item.type === 'd') return false;
				const fileContent = await item.decrypt();
				const hash = crypto.createHash('sha256').update(fileContent.content).digest();
				if(Buffer.compare(hash, hashes[i]) !== 0) return false;
			}
			return true;
		}
		
		await expect(testFunction()).resolves.toBe(true);
	});
	test('Create a random tree within a vault', async () => {
		const sample = await TargetFS.create(provider, dir, 3, 32);
		await expect(sample.verify()).resolves.toBe(null);
	});
	test('Create a random tree with very long names within a vault', async () => {
		const sample = await TargetFS.create(provider, dir, 4, 777);
		await expect(sample.verify()).resolves.toBe(null);
	});
	test('Create a random tree within a vault, and delete some folders at random', async () => {
		const sample = await TargetFS.create(provider, dir, 5, 32);
		const f = async () => {
			for(const k in sample.tree){
				// Open a directory with parent ID of dirId
				const dirId = k as DirID;
				for(const item of sample.tree[dirId]){
					if(item.type === 'f') continue;
					// Randomly select a directory within that parent directory
					if(Math.floor(Math.random() * 5) === 0){
						sample.delFolder(dirId, item.id);
						const items = await sample.vault.listItems(dirId);
						const dir = items.find(i => i.decryptedName === item.name) as EncryptedDir;
						if(dir) await dir.deleteDir();
						else throw new Error(`Item not found: ${dirId}`);
					}
				}
			}
			return await sample.verify();
		}
		await expect(f()).resolves.toBe(null);
	});
});