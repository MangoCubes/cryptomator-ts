import { afterAll, describe, expect, test } from '@jest/globals';
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

describe('Test creating a vault', () => {
	const provider = new LocalStorageProvider();
	const dir = path.resolve(__dirname, 'encryptionTest');
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
	afterAll(async () => {
		const testVaults = await provider.listItems(dir);
		for(const v of testVaults) await provider.removeDir(v.fullName);
	});
});