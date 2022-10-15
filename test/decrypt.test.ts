import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';

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
});
