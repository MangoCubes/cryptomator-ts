import { describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';

describe('Test creating a vault', () => {
	const provider = new LocalStorageProvider();
	test('Try creating a vault', async () => {
		const dir = path.resolve(__dirname, 'Test2');
		await Vault.create(provider, dir, '12341234', {
			name: null,
			createHere: true
		});
		await expect(Vault.open(provider, dir, '12341234', null)).resolves.not.toThrowError();
	});
});