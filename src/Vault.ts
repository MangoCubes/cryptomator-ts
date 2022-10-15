import { scrypt } from "scrypt-js";
import { DataProvider } from "./DataProvider";
import { Base64Str, EncryptionKey, MACKey } from "./types";

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

type Masterkey = {
	primaryMasterKey: Base64Str;
	hmacMasterKey: Base64Str;
	scryptBlockSize: number;
	scryptCostParam: number;
	scryptSalt: Base64Str;
	versionMac: Base64Str;
}

export class Vault {

	constructor(public provider: DataProvider, public dir: string, public name: string | null, private encKey: EncryptionKey, private macKey: MACKey){
		
	}

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
		if (!dir.endsWith('/')) dir += '/';
		const jwt = await provider.readFileString(dir + 'vault.cryptomator'); //The JWT is signed using the 512 bit raw masterkey
		const mk = JSON.parse(await provider.readFileString(dir + 'masterkey.cryptomator')) as Masterkey;
		const kekBuffer = await scrypt(new TextEncoder().encode(password), base64Decode(mk.scryptSalt), mk.scryptCostParam, mk.scryptBlockSize, 1, 32);
		const kek = await window.crypto.subtle.importKey(
			'raw',
			kekBuffer,
			'AES-KW',
			false,
			['unwrapKey']
		);
		const encKey = await window.crypto.subtle.unwrapKey(
			'raw',
			base64Decode(mk.primaryMasterKey),
			kek,
			'AES-KW',
			'AES-CTR',
			true,
			['encrypt', 'decrypt']
		) as EncryptionKey;
		// const extracted = await window.crypto.subtle.exportKey('raw', encKey);
		const macKey = await window.crypto.subtle.unwrapKey(
			'raw',
			base64Decode(mk.hmacMasterKey),
			kek,
			'AES-KW',
			'AES-CTR',
			false,
			[]
		) as MACKey;
		return new Vault(provider, dir, name, encKey, macKey);
	}
}

function base64Decode(encoded: Base64Str): Uint8Array {
	let decoded = window.atob(encoded);
    let bytes = new Uint8Array(decoded.length);
    for (var i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
    return bytes;
}