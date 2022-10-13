import { DataProvider } from "./DataProvider";

type VaultConfigHeader = {
	kid: string;
	typ: 'JWT';
	alg: 'HS256' | 'HS384' | 'HS512';
}

type VaultConfig = {
	format: number;
	shorteningThreshold: number;
	jti: string;
	cipherCombo: 'SIV_CTRMAC';
}

export class Vault {
	/**
	 * Open an existing vault
	 * @param provider Data provider
	 * @param dir Directory of the vault that contains 'masterkey.cryptomator' and 'd' directory
	 * @param password Password of the vault
	 * @param name Name of the vault, may be null
	 * 
	 * Potential options later on:
	 * Custom masterkey file
	 * Custom vault.cryptomator file
	 */
	static async open(provider: DataProvider, dir: string, password: string, name: string | null) {
		if (dir.endsWith('/')) dir += '/';
		const jwt = provider.readFileString(dir + 'vault.cryptomator'); //The JWT is signed using the 512 bit raw masterkey

	}
}