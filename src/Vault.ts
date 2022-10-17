import { AES } from "@stablelib/aes";
import { SIV } from "@stablelib/siv";
import b32 from "base32-encoding";
import { scrypt } from "scrypt-js";
import { DataProvider } from "./DataProvider";
import { Base64Str, DirID, EncryptionKey, Item, MACKey } from "./types";
import { base64url, jwtVerify } from "jose";
import { DecryptionError, DecryptionTarget, InvalidVaultError } from "./Errors";
import { EncryptedItem } from "./EncryptedItem";

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
		if (dir.endsWith('/')) dir = dir.slice(0, -1);
		const token = await provider.readFileString(dir + '/vault.cryptomator'); //The JWT is signed using the 512 bit raw masterkey
		const mk = JSON.parse(await provider.readFileString(dir + '/masterkey.cryptomator')) as Masterkey;
		const kekBuffer = await scrypt(new TextEncoder().encode(password), base64Decode(mk.scryptSalt), mk.scryptCostParam, mk.scryptBlockSize, 1, 32);
		let kek: CryptoKey;
		try {
			kek = await crypto.subtle.importKey(
				'raw',
				kekBuffer,
				'AES-KW',
				false,
				['unwrapKey']
			);
		} catch(e) {
			throw new DecryptionError(DecryptionTarget.Vault, null);
		}
		const encKey = await crypto.subtle.unwrapKey(
			'raw',
			base64Decode(mk.primaryMasterKey),
			kek,
			'AES-KW',
			'AES-CTR',
			true,
			['encrypt', 'decrypt']
		) as EncryptionKey;
		const extractedEnc = new Uint8Array(await crypto.subtle.exportKey('raw', encKey));
		const macKey = await crypto.subtle.unwrapKey(
			'raw',
			base64Decode(mk.hmacMasterKey),
			kek,
			'AES-KW',
			'AES-CTR',
			true,
			[]
		) as MACKey;
		const extractedMac = new Uint8Array(await crypto.subtle.exportKey('raw', macKey));
		const buffer = new Uint8Array(64);
		buffer.set(extractedMac, 0);
		buffer.set(extractedEnc, 32);
		const siv = new SIV(AES, buffer);
		buffer.set(extractedEnc, 0);
		buffer.set(extractedMac, 32);
		extractedMac.fill(0);
		extractedEnc.fill(0);
		try {
			jwtVerify(token, new Uint8Array(buffer));
		} catch(e) {
			throw new InvalidVaultError();
		}
		buffer.fill(0);
		return new Vault(provider, dir, name, encKey, macKey, siv);
	}

	async getDir(dirId: DirID){
		const sivId = this.siv.seal([], new TextEncoder().encode(dirId));
		const ab = await crypto.subtle.digest('SHA-1', sivId);
		const dirHash = b32.stringify(new Uint8Array(ab), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
		return `${this.dir}/d/${dirHash.substring(0, 2)}/${dirHash.substring(2)}`;
	}

	async listEncrypted(dirId: DirID){
		const dir = await this.getDir(dirId);
		const items = await this.provider.listItems(dir);
		return items;
	}

	async getRootDir(){
		return await this.getDir('' as DirID);
	}

	async decryptFileName(item: Item, parent: DirID): Promise<string>{
		let name;
		if(item.name.endsWith('.c9r')) name = item.name.slice(0, -4);
		else name = item.name;
		const decrypted = this.siv.open([new TextEncoder().encode(parent)], base64url.decode(name));
		if(decrypted === null) throw new DecryptionError(DecryptionTarget.Filename, item);
		return new TextDecoder().decode(decrypted);
	}

	async listItems(dirId: DirID){
		const enc = await this.listEncrypted(dirId);
		const pendingNameList: Promise<string>[] = [];
		for(const item of enc) pendingNameList.push(this.decryptFileName(item, '' as DirID));
		const names = await Promise.all(pendingNameList);
		const items: EncryptedItem[] = [];
		for(let i = 0; i < enc.length; i++) items.push(new EncryptedItem(enc[i].name, names[i], dirId, enc[i].type, enc[i].lastMod, enc[i].size, enc[i].fullName));
		return items;
	}
}

function base64Decode(encoded: Base64Str): Uint8Array {
	let decoded = atob(encoded);
    let bytes = new Uint8Array(decoded.length);
    for (var i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
    return bytes;
}