import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { EncryptedFile } from '../src/encrypted/EncryptedFile';
import { DirID } from '../src/types';

describe('Test creating a vault', () => {
	const provider = new LocalStorageProvider();
	test('Try creating a vault', async () => {
		const dir = path.resolve(__dirname);
		await Vault.create(provider, dir, '12341234', {
			name: 'Test2'
		});
		await expect(Vault.open(provider, path.resolve(__dirname, 'Test2'), '12341234', null)).resolves.not.toThrowError();
	});
	test.only('Try adding a file in root', async () => {
		const dir = path.resolve(__dirname);
		const v = await Vault.create(provider, dir, '12341234', {
			name: 'Test3'
		});
		const testFunction = async () => {
			await EncryptedFile.encrypt(v, 'HelloWorld.txt', '' as DirID, 'HELLO WORLD!');
			await EncryptedFile.encrypt(v, 'HelloWorld2.txt', '' as DirID, 'ABCD'.repeat(1024 * 1024) + '123412341234');
			const firstFile = (await v.listItems('' as DirID)).find(i => i.decryptedName === 'HelloWorld.txt') as EncryptedFile;
			const secondFile = (await v.listItems('' as DirID)).find(i => i.decryptedName === 'HelloWorld2.txt') as EncryptedFile;
			const decrypted = await firstFile.decryptAsString();
			const decrypted2 = await secondFile.decryptAsString();
			return decrypted.content.includes('HELLO WORLD!') && decrypted2.content.includes('123412341234');
		}
		
		await expect(testFunction()).resolves.toBe(true);
	});
});