import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { DirID, ItemPath } from '../src/types';
import { EncryptedFile } from '../src/encrypted/EncryptedFile';
import { InvalidSignatureError } from '../src/Errors';

async function decrypt(provider: LocalStorageProvider, password: string, options?: {
	vaultFile?: ItemPath
}): Promise<Vault>{
	const v = await Vault.open(provider, path.resolve(__dirname, 'Test'), password, 'Test Vault', options ? options : {vaultFile: path.resolve(__dirname, 'Test', 'vault-valid.cryptomator') as ItemPath});
	return v;
}

describe('Test opening an existing vault', () => {
	const provider = new LocalStorageProvider();
	test('Wrong password should throw an error', async () => {
		await expect(decrypt(provider, 'qq11@11')).rejects.toThrowError();
		await expect(decrypt(provider, '')).rejects.toThrowError();
		await expect(decrypt(provider, 'qq11@@@11')).rejects.toThrowError();
	});

	test('Vault opening should fail if vault.cryptomator is invalid', async () => {
		await expect(decrypt(provider, 'qq11@@11', {vaultFile: path.resolve(__dirname, 'Test', 'vault-corrupted.cryptomator') as ItemPath})).rejects.toThrowError(InvalidSignatureError);
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

	test('Try getting directory ID of folders in root', async () => {
		const vault = await decrypt(provider, 'qq11@@11');
		const items = await vault.listItems('' as DirID);
		const folderNames: Promise<DirID>[] = [];
		for(const item of items){
			if(item.type === 'd') folderNames.push(item.getDirId());
		}
		await expect(Promise.all(folderNames)).resolves.not.toThrowError();
	});

	test('Try decrypting header of a file', async () => {
		const vault = await decrypt(provider, 'qq11@@11');
		const items = await vault.listItems('' as DirID);
		const firstFile = items.find(i => i.type === 'f');
		const pendingContentKey = (firstFile! as EncryptedFile).decryptHeader();
		await expect(pendingContentKey).resolves.not.toThrowError();
	});

	// test('Try decrypting a file', async () => {
	// 	const vault = await decrypt(provider, 'qq11@@11');
	// 	const items = await vault.listItems('8ef3bbd6-6f41-498a-a785-735c5b1b1f75' as DirID);
	// 	const firstFile = items.find(i => i.type === 'f');
	// 	const pendingContent = (firstFile! as EncryptedFile).decrypt();
	// 	await expect(pendingContent).resolves.not.toThrowError();
	// });
});
