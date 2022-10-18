import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { DirID } from '../src/types';
import { EncryptedItem } from '../src/EncryptedItem';

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
	let vault: Vault;
	test('Try opening a vault with a correct password', async () => {
		const pendingVault = decrypt(provider, 'qq11@@11');
		await expect(pendingVault).resolves.not.toThrowError();
		vault = await pendingVault;
	});
	test('Testing root directory id generation', async () => {
		await expect(vault.getRootDir()).resolves.not.toThrowError();
	});
	test('Try listing encrypted items in root', async () => {
		const pendingList = vault.listEncrypted('' as DirID);
		expect(pendingList).resolves.not.toThrowError();
	});
	
	let items: EncryptedItem[];
	test('Try decrypting names of items in root', async () => {
		const pendingItems = vault.listItems('' as DirID);
		expect(pendingItems).resolves.not.toThrowError();
		items = await pendingItems;
	});

	test('Try decrypting header of a file', async () => {
		const firstFile = items.find(i => i.type === 'f');
		const pendingContentKey = firstFile!.decryptHeader();
		expect(pendingContentKey).resolves.not.toThrowError();
		console.log(await pendingContentKey);
	});
});
