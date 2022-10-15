import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';

async function decrypt(provider: LocalStorageProvider): Promise<Vault>{
	const v = await Vault.open(provider, path.resolve(__dirname, 'Test'), 'qq11@@11', 'Test Vault');
	return v;
}

describe('Test opening an existing vault', () => {
	const provider = new LocalStorageProvider();
	test('Check if LocalStorageProvider works', async () => {
		expect(await provider.readFileString(path.resolve(__dirname, 'Test', 'qq11@@11.txt'))).toEqual('Hello world');
	});
	let vault: Vault;
	test('Try opening a vault', async () => {
		const pendingVault = decrypt(provider);
		await expect(pendingVault).resolves.not.toThrowError();
		vault = await pendingVault;
	});
});
