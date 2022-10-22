import { AES } from "@stablelib/aes";
import { SIV } from "@stablelib/siv";
import b32 from "base32-encoding";
import { scrypt } from "scrypt-js";
import { DataProvider } from "./DataProvider";
import { DirID, EncryptionKey, Item, ItemPath, MACKey } from "./types";
import { base64url, jwtVerify, SignJWT } from "jose";
import { DecryptionError, DecryptionTarget, InvalidSignatureError } from "./Errors";
import { EncryptedItem } from "./encrypted/EncryptedItemBase";
import { EncryptedDir } from "./encrypted/EncryptedDir";
import { EncryptedFile } from "./encrypted/EncryptedFile";
import Base64 from "js-base64";

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
	primaryMasterKey: string;
	hmacMasterKey: string;
	scryptBlockSize: number;
	scryptCostParam: number;
	scryptSalt: string;
	versionMac: string;
	version: 999;
}

type CreateVaultOpts = ({
	/**
	 * Name of this vault.
	 * If set, a subdirectory with this name will be created under the specified folder.
	 */
	name: string;
} | {
	name: null;
	/**
	 * If true, the vault will be created created directly in the supplied directory.
	 * In other words, the vault.cryptomator and masterkey.cryptomator will be created in the specified directory.
	 */
	createHere: true;
}) & Partial<{
	/**
	 * Currently, other versions are not supported.
	 */
	format: 8;
	/**
	 * Shortening threshold is currently hardcoded to 220, the default for official Cryptomator softwares.
	 */
	shorteningThreshold: 220;
	/**
	 * Defaults to 32768 as per recommendation specified at https://github.com/cryptomator/cryptomator/issues/611.
	 */
	scryptCostParam: number;
	/**
	 * Defaults to 8.
	 */
	scryptBlockSize: number;
}>


/**
 * Cryptomator vault object
 */
export class Vault {
	private constructor(public provider: DataProvider, public dir: string, public name: string | null, public encKey: EncryptionKey, public macKey: MACKey, private siv: SIV){
		
	}

	/**
	 * Create a vault.
	 * @param provider File system provider
	 * @param dir Directory to create this vault
	 * @param password Vault password
	 * @param options Vault options, check type properties for more information
	 * @returns The vault object for the newly created vault
	 * 
	 * Currently, custom masterkey.cryptomator location and algorithm other than HS256 is not supported.
	 * As a result, vault.cryptomator's decoded header will always be the same.
	 */
	static async create(
		provider: DataProvider,
		dir: string,
		password: string,
		options: CreateVaultOpts
	) {
		const sBlockSize = options.scryptBlockSize ?? 8;
		const sCostParam = options.scryptCostParam ?? 32768;
		const format = options.format ?? 8;
		if (dir.endsWith('/')) dir = dir.slice(0, -1);
		const salt = crypto.getRandomValues(new Uint8Array(32));
		const kekBuffer = await scrypt(new TextEncoder().encode(password), salt, sCostParam, sBlockSize, 1, 32);
		const encKeyBuffer = crypto.getRandomValues(new Uint8Array(32));
		const macKeyBuffer = crypto.getRandomValues(new Uint8Array(32));
		const buffer = new Uint8Array(64);
		buffer.set(macKeyBuffer, 0);
		buffer.set(encKeyBuffer, 32);
		const siv = new SIV(AES, buffer);
		buffer.set(encKeyBuffer, 0);
		buffer.set(macKeyBuffer, 32);		

		const kek = await crypto.subtle.importKey('raw', kekBuffer, 'AES-KW', false, ['wrapKey']);
		kekBuffer.fill(0);
		const encKey = await crypto.subtle.importKey('raw', encKeyBuffer, 'AES-CTR', true, ['encrypt', 'decrypt']) as EncryptionKey;
		const macKey = await crypto.subtle.importKey('raw', macKeyBuffer, {
			name: 'HMAC',
			hash: {name: 'SHA-256'}
		}, true, ['sign']) as MACKey;
		

		encKeyBuffer.fill(0);
		macKeyBuffer.fill(0);

		const wrappedEncKey = new Uint8Array(await crypto.subtle.wrapKey(
			'raw',
			encKey,
			kek,
			'AES-KW'
		));

		const wrappedMacKey = new Uint8Array(await crypto.subtle.wrapKey(
			'raw',
			macKey,
			kek,
			'AES-KW'
		));

		const versionMac = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, new TextEncoder().encode(`${format}`)));
		const mk: Masterkey = {
			primaryMasterKey: Base64.fromUint8Array(wrappedEncKey),
			hmacMasterKey: Base64.fromUint8Array(wrappedMacKey),
			scryptBlockSize: sBlockSize,
			scryptCostParam: sCostParam,
			scryptSalt: Base64.fromUint8Array(salt),
			versionMac: Base64.fromUint8Array(versionMac),
			version: 999
		}

		const vaultFile = await new SignJWT({
			format: format,
			shorteningThreshold: options.shorteningThreshold ?? 220,
			jti: crypto.randomUUID(),
			cipherCombo: 'SIV_CTRMAC'
		}).setProtectedHeader({
			alg: 'HS256',
			kid: 'masterkeyfile:masterkey.cryptomator',
			typ: 'JWT'
		}).sign(buffer);
		buffer.fill(0);

		await provider.writeFile(`${dir}/masterkey.cryptomator`, JSON.stringify(mk));
		await provider.writeFile(`${dir}/vault.cryptomator`, vaultFile);
		await provider.createDir(`${dir}/d`);

		const vault = new Vault(provider, dir, options.name, encKey, macKey, siv);
		const rootDir = await vault.getRootDir();
		await provider.createDir(rootDir, true);

		return vault;
	}

	/**
	 * Open an existing vault
	 * @param provider Data provider
	 * @param dir Directory of the vault that contains 'masterkey.cryptomator' and 'd' directory
	 * @param password Password of the vault
	 * @param name Name of the vault, may be null
	 * @param options Various options to pass to decrypting vault
	 * @param options.vaultFile: Absolute directory of the vault.cryptomator file
	 * @param options.masterkeyFile: Absolute directory of the masterkey.cryptomator file
	 * @throws DecryptionError if the given password is wrong
	 * @throws InvalidSignatureError if the integrity of vault.cryptomator file cannot be verified
	 */
	static async open(
			provider: DataProvider,
			dir: string,
			password: string,
			name: string | null,
			options?: {
				vaultFile?: ItemPath
				masterkeyFile?: ItemPath
			}
		) {
		if (dir.endsWith('/')) dir = dir.slice(0, -1);
		const token = await provider.readFileString(options?.vaultFile ? options.vaultFile : dir + '/vault.cryptomator'); //The JWT is signed using the 512 bit raw masterkey
		const mk = JSON.parse(await provider.readFileString(options?.masterkeyFile ? options.masterkeyFile : dir + '/masterkey.cryptomator')) as Masterkey;
		const kekBuffer = await scrypt(new TextEncoder().encode(password), Base64.toUint8Array(mk.scryptSalt), mk.scryptCostParam, mk.scryptBlockSize, 1, 32);
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
		kekBuffer.fill(0);
		const encKey = await crypto.subtle.unwrapKey(
			'raw',
			Base64.toUint8Array(mk.primaryMasterKey),
			kek,
			'AES-KW',
			'AES-CTR',
			true,
			['encrypt', 'decrypt']
		) as EncryptionKey;
		const extractedEnc = new Uint8Array(await crypto.subtle.exportKey('raw', encKey));
		const macKey = await crypto.subtle.unwrapKey(
			'raw',
			Base64.toUint8Array(mk.hmacMasterKey),
			kek,
			'AES-KW',
			{
				name: 'HMAC',
				hash: {name: 'SHA-256'}
			},
			true,
			['sign']
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
			await jwtVerify(token, buffer);
		} catch(e) {
			throw new InvalidSignatureError(DecryptionTarget.Vault);
		}
		buffer.fill(0);
		return new Vault(provider, dir, name, encKey, macKey, siv);
	}

	/**
	 * Accepts a directory ID, and returns the directory of the corresponding folder
	 * @param dirId ID of the directory
	 * @returns Corresponding _absolute_ directory
	 */
	async getDir(dirId: DirID){
		const sivId = this.siv.seal([], new TextEncoder().encode(dirId));
		const ab = await crypto.subtle.digest('SHA-1', sivId);
		const dirHash = b32.stringify(new Uint8Array(ab), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
		return `${this.dir}/d/${dirHash.substring(0, 2)}/${dirHash.substring(2)}`;
	}

	/**
	 * List all files under a given directory ID
	 * @param dirId ID of the directory
	 * @returns Items within that folder, not ready for decryption
	 */
	async listEncrypted(dirId: DirID){
		const dir = await this.getDir(dirId);
		const items = await this.provider.listItems(dir);
		return items.filter(i => i.name !== 'dirid.c9r'); // TODO: Add a function that decrypts this
	}

	/**
	 * Get directory of the root directory
	 * @returns Encrypted directory that corresponds to the root directory (Directory with ID of "")
	 */
	async getRootDir(){
		return await this.getDir('' as DirID);
	}

	/**
	 * Decrypts a file name
	 * @param item Encrypted file
	 * @param parent ID of the parent directory
	 * @returns Decrypted file name as string
	 * @throws DecryptionError If file name cannot be decrypted
	 */
	async decryptFileName(item: Item, parent: DirID): Promise<string>{
		let name;
		if(item.name.endsWith('.c9r')) name = item.name.slice(0, -4);
		else name = item.name;
		const decrypted = this.siv.open([new TextEncoder().encode(parent)], base64url.decode(name));
		if(decrypted === null) throw new DecryptionError(DecryptionTarget.ItemName, item);
		return new TextDecoder().decode(decrypted);
	}

	/**
	 * Return an encrypted file name
	 * @param name Original name of the file
	 * @param parent Directory ID of the parent folder
	 * @returns Encrypted file name
	 */
	async encryptFileName(name: string, parent: DirID): Promise<string>{
		const encrypted = this.siv.seal([new TextEncoder().encode(parent)], new TextEncoder().encode(name));
		return base64url.encode(encrypted);
	}

	/**
	 * List all files, ready for decrypting contents
	 * @param dirId ID of the directory
	 * @returns Encrypted items in that directory
	 */
	async listItems(dirId: DirID){
		const enc = await this.listEncrypted(dirId);
		const pendingNameList: Promise<string>[] = [];
		for(const item of enc) pendingNameList.push(this.decryptFileName(item, dirId));
		const names = await Promise.all(pendingNameList);
		const items: EncryptedItem[] = [];
		for(let i = 0; i < enc.length; i++) {
			const item = enc[i];
			if(item.type === 'd') items.push(await EncryptedDir.open(this, item.name, item.fullName, names[i], dirId, item.lastMod));
			if(item.type === 'f') items.push(new EncryptedFile(this, item.name, item.fullName, names[i], dirId, item.lastMod, item.size));
		}
		return items;
	}

	/**
	 * Create a directory under a given directory ID
	 * @param name Name of the folder
	 * @param parent Directory ID of the parent folder
	 * @returns Directory ID of the new folder
	 */
	async createDirectory(name: string, parent: DirID){
		const dirId = crypto.randomUUID() as DirID;
		const encDir = await this.getDir(dirId);
		const dir = `${encDir}/${await this.encryptFileName(name, parent)}.c9r`;
		await this.provider.createDir(dir, true);
		await this.provider.writeFile(`${dir}/dir.c9r`, dirId);
		return dirId;
	}
}