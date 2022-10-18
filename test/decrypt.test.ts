import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { DirID } from '../src/types';
import { EncryptedFile } from '../src/encrypted/EncryptedFile';

async function decrypt(provider: LocalStorageProvider, password: string): Promise<Vault>{
	const v = await Vault.open(provider, path.resolve(__dirname, 'Test'), password, 'Test Vault');
	return v;
}

describe('Test opening an existing vault', () => {
	const provider = new LocalStorageProvider();
	test('Wrong password should throw an error', async () => {
		await expect(decrypt(provider, 'qq11@11')).rejects.toThrowError();
		await expect(decrypt(provider, '')).rejects.toThrowError();
		await expect(decrypt(provider, 'qq11@@@11')).rejects.toThrowError();
	});

	test('Try opening a vault with a correct password', async () => {
		await expect(decrypt(provider, 'qq11@@11')).resolves.not.toThrowError();
	});

	test('Testing root directory id generation', async () => {
		const vault = await decrypt(provider, 'qq11@@11');
		await expect(vault.getRootDir()).resolves.not.toThrowError();
	});

	test('Try listing encrypted items in root', async () => {
		const vault = await decrypt(provider, 'qq11@@11');
		await expect(vault.listEncrypted('' as DirID)).resolves.not.toThrowError();
	});
	
	test('Try decrypting names of items in root', async () => {
		const vault = await decrypt(provider, 'qq11@@11');
		await expect(vault.listItems('' as DirID)).resolves.not.toThrowError();
	});

	test('Try decrypting header of a file', async () => {
		const vault = await decrypt(provider, 'qq11@@11');
		const items = await vault.listItems('' as DirID);
		const firstFile = items.find(i => i.type === 'f');
		const pendingContentKey = (firstFile! as EncryptedFile).decryptHeader();
		await expect(pendingContentKey).resolves.not.toThrowError();
	});
});
