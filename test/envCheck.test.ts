import { describe, expect, test } from '@jest/globals';
import path from "path";
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';

describe('Test opening an existing vault', () => {
	test('Check if subtle crypto and TextEncoder exists', () => {
		expect(crypto.subtle).toBeTruthy();
		expect(new TextEncoder()).toBeTruthy();
	})
	const provider = new LocalStorageProvider();
	test('Check if LocalStorageProvider works', async () => {
		expect(await provider.readFileString(path.resolve(__dirname, 'Test', 'qq11@@11.txt'))).toEqual('Yes, this is the vault password.');
	});
});
