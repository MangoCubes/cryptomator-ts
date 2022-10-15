import { AES } from "@stablelib/aes";
import { SIV } from "@stablelib/siv";
import b32 from "base32-encoding";
import { scrypt } from "scrypt-js";
import { DataProvider } from "./DataProvider";
import { Base64Str, DirID, EncryptionKey, MACKey } from "./types";

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

	constructor(public provider: DataProvider, public dir: string, public name: string | null, private encKey: EncryptionKey, private macKey: MACKey, private siv: SIV){
		
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
		const extractedEnc = await window.crypto.subtle.exportKey('raw', encKey);
		const macKey = await window.crypto.subtle.unwrapKey(
			'raw',
			base64Decode(mk.hmacMasterKey),
			kek,
			'AES-KW',
			'AES-CTR',
			true,
			[]
		) as MACKey;
		const extractedMac = await window.crypto.subtle.exportKey('raw', macKey);
		const sivArr = new Uint8Array(64);
		sivArr.set(new Uint8Array(extractedMac), 0);
		sivArr.set(new Uint8Array(extractedEnc), 32);
		const siv = new SIV(AES, sivArr);
		return new Vault(provider, dir, name, encKey, macKey, siv);
	}

	async getDir(dirId: DirID){
		const sivId = this.siv.seal([], new TextEncoder().encode(dirId));
		const ab = await crypto.subtle.digest('SHA-1', sivId);
		const dirHash = b32.stringify(new Uint8Array(ab), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
		return `d/${dirHash.substring(0, 2)}/${dirHash.substring(2)}`
	}

	async getRootDir(){
		return await this.getDir('' as DirID);
	}
}

function base64Decode(encoded: Base64Str): Uint8Array {
	let decoded = window.atob(encoded);
    let bytes = new Uint8Array(decoded.length);
    for (var i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
    return bytes;
}