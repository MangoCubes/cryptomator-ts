import { afterAll, beforeAll, describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { EncryptedFile } from '../src/encrypted/EncryptedFile';
import { DirID } from '../src/types';
import { DecryptionError, DecryptionTarget } from '../src/Errors';
import crypto from 'node:crypto';

async function randomBuffer(size: number): Promise<Uint8Array>{
	const arr = new Uint8Array(size);
	for(let i = 0; i < size; i++) arr[i] = Math.floor(Math.random() * 256);
	return arr;
}

/**
 * Creates random files and folders
 * 0: Create a file in the current directory. Name is a random UUID, and its content is SHA-256 of the decrypted name.
 * 1: Create a directory, and go into it. Name is a randomly generated UUID.
 * 2: Go up a directory. Unavailable if the current directory is root.
 */
async function genRandomVault(provider: LocalStorageProvider, dir: string, id: number){
	const v = await Vault.create(provider, dir, '12341234', {
		name: `encTest${id}`
	});
	const path: DirID[] = [];
	for(let i = 0; i < 100; i++){
		const action = Math.floor(Math.random() * (path.length === 0 ? 2 : 3));
		const last = path.length === 0 ? '' as DirID : path[path.length - 1];
		if(action === 0){
			const name = crypto.randomUUID();
			const content = crypto.createHash('sha256').update(name).digest();
			await EncryptedFile.encrypt(v, name, last, content);
		} else if(action === 1){
			const name = crypto.randomUUID();
			const dir = await v.createDirectory(name, last);
			path.push(await dir.getDirId());
		} else if(action === 2) path.pop();
	}
	return v;
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
		const v = await genRandomVault(provider, dir, 3);
	});
});