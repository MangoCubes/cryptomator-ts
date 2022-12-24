import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { DirID, ItemPath } from '../src/types';
import { EncryptedFile } from '../src/encrypted/EncryptedFile';
import { InvalidSignatureError } from '../src/Errors';

async function decrypt(provider: LocalStorageProvider, password: string, vaultNumber: number, options?: {
	vaultFile?: ItemPath
}): Promise<Vault>{
	const v = await Vault.open(
		provider,
		path.resolve(__dirname, 'decryptionTest', `vault${vaultNumber}`),
		password,
		'Test Vault',
		options
		? options
		: {
			vaultFile: vaultNumber === 1 
			? path.resolve(__dirname, 'decryptionTest', 'vault1', 'vault-valid.cryptomator') as ItemPath
			: path.resolve(__dirname, 'decryptionTest', `vault${vaultNumber}`, 'vault.cryptomator') as ItemPath
		});
	return v;
}

async function saveDecrypted(provider: LocalStorageProvider, file: EncryptedFile) {
	const decrypted = await file.decryptAsString();
	const testFileName = new Date().getTime() + decrypted.title.slice(-20);
	console.log('Output generated: ' + testFileName)
	const decryptedFile = path.resolve(__dirname, 'output', testFileName);
	await provider.writeFile(decryptedFile, decrypted.content);
	return decryptedFile;
}

describe('Test opening an existing vault', () => {
	const provider = new LocalStorageProvider();
	test('Wrong password should throw an error', async () => {
		await expect(decrypt(provider, 'qq11@11', 1)).rejects.toThrowError();
		await expect(decrypt(provider, '', 1)).rejects.toThrowError();
		await expect(decrypt(provider, 'qq11@@@11', 1)).rejects.toThrowError();
	});

	test('Vault opening should fail if vault.cryptomator is invalid', async () => {
		await expect(decrypt(provider, 'qq11@@11', 1, {vaultFile: path.resolve(__dirname, 'decryptionTest', 'vault1', 'vault-corrupted.cryptomator') as ItemPath})).rejects.toThrowError(InvalidSignatureError);
	});

	test('Try opening a vault with a correct password', async () => {
		await expect(decrypt(provider, 'qq11@@11', 1)).resolves.not.toThrowError();
	});

	test('Try listing encrypted items in root', async () => {
		const vault = await decrypt(provider, 'qq11@@11', 1);
		await expect(vault.listEncrypted('' as DirID)).resolves.not.toThrowError();
	});
	
	test('Try decrypting names of items in root', async () => {
		const vault = await decrypt(provider, 'qq11@@11', 1);
		const f = async () => {
			const count = [0, 0];
			const items = await vault.listItems('' as DirID);
			for(const i of items){
				if(i.type === 'd') count[0]++;
				else if(i.type === 'f') count[1]++;
			}
			return count;
		}
		await expect(f()).resolves.toStrictEqual([4, 1]);
	});

	test('Try decrypting names of items in root using root dir object', async () => {
		const vault = await decrypt(provider, 'qq11@@11', 1);
		const f = async () => {
			const count = [0, 0];
			const items = await (await vault.getRootDir()).listItems();
			for(const i of items){
				if(i.type === 'd') count[0]++;
				else if(i.type === 'f') count[1]++;
			}
			return count;
		}
		await expect(f()).resolves.toStrictEqual([4, 1]);
	});

	test('Try getting directory ID of folders in root', async () => {
		const vault = await decrypt(provider, 'qq11@@11', 1);
		const items = await vault.listItems('' as DirID);
		const folderNames: Promise<DirID>[] = [];
		for(const item of items){
			if(item.type === 'd') folderNames.push(item.getDirId());
		}
		await expect(Promise.all(folderNames)).resolves.not.toThrowError();
	});

	test('Try decrypting header of a file', async () => {
		const vault = await decrypt(provider, 'qq11@@11', 1);
		const items = await vault.listItems('' as DirID);
		const firstFile = items.find(i => i.type === 'f');
		const pendingContentKey = (firstFile! as EncryptedFile).decryptHeader();
		await expect(pendingContentKey).resolves.not.toThrowError();
	});

	test('Try decrypting a file', async () => {
		const vault = await decrypt(provider, 'qq11@@11', 1);
		const items = await vault.listItems('' as DirID);
		const firstFile = items.find(i => i.decryptedName === 'WELCOME.rtf') as EncryptedFile;
		const decryptedFile = await saveDecrypted(provider, firstFile);
		const read = async () => {
			const str = await provider.readFileString(decryptedFile);
			return str.includes('Cryptomator');
		}
		await expect(read()).resolves.toBe(true);
	});

	test('Try listing items with long names', async () => {
		const vault = await decrypt(provider, '12341234', 2);
		const f = async () => {
			const items = await vault.listItems('' as DirID);
			const longItems = items.filter(i => i.decryptedName.length > 220);
			const foundDir = longItems.some(i => i.decryptedName.length > 220 && i.decryptedName.includes('A'.repeat(220)))
			const foundFile = longItems.some(i => i.decryptedName.length > 220 && i.decryptedName.includes('B'.repeat(220)) && i.decryptedName.endsWith('.txt'));
			return foundDir && foundFile;
		}
		await expect(f()).resolves.toBe(true);
	});

	test('Try decrypting file with long name', async () => {
		const vault = await decrypt(provider, '12341234', 2);
		const items = await vault.listItems('' as DirID);
		const longItems = items.filter(i => i.decryptedName.length > 220);
		const foundFile = longItems.find(i => i.decryptedName.length > 220 && i.decryptedName.includes('B'.repeat(220)) && i.decryptedName.endsWith('.txt')) as EncryptedFile;
		const decryptedFile = await saveDecrypted(provider, foundFile);
		const read = async () => {
			const str = await provider.readFileString(decryptedFile);
			return str.includes('Hello world');
		}
		await expect(read()).resolves.toBe(true);
	});
});
