import { base64url } from "jose";
import { DecryptionTarget, InvalidSignatureError } from "../Errors";
import { ContentKey, DirID, File, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedDir } from "./EncryptedDir";
import { EncryptedItemBase } from "./EncryptedItemBase";

type Header = {
	contentKey: ContentKey;
	nonce: Uint8Array;
}

export class EncryptedFile extends EncryptedItemBase implements File{
	type: 'f';

	static async encryptChunk(vault: Vault, header: Header, chunk: Uint8Array, chunkNum: number): Promise<Uint8Array>{
		const nonce = crypto.getRandomValues(new Uint8Array(16));
		const encrypted = new Uint8Array(await crypto.subtle.encrypt(
			{
				name: 'AES-CTR',
				counter: nonce,
				length: 32
			},
			header.contentKey,
			chunk
		));
		const payload = new Uint8Array(40 + chunk.byteLength);
		payload.set(header.nonce, 0);
		const cCount = new Uint8Array(BigUint64Array.from([BigInt(chunkNum)]).buffer);
		cCount.reverse();
		payload.set(cCount, 16);
		payload.set(nonce, 24);
		payload.set(encrypted, 40);
		const sig = new Uint8Array(await crypto.subtle.sign('HMAC', vault.macKey, payload));
		const result = new Uint8Array(16 + chunk.byteLength + 32);
		result.set(nonce, 0);
		result.set(encrypted, 16);
		result.set(sig, 16 + chunk.byteLength);
		return result;
	}

	static async encrypt(vault: Vault, name: string, parent: DirID | null | EncryptedDir, content: Uint8Array | string): Promise<EncryptedFile>{
		if(typeof(content) === 'string') content = new TextEncoder().encode(content);
		const nonce = crypto.getRandomValues(new Uint8Array(16));
		const contentKeyBuffer = crypto.getRandomValues(new Uint8Array(32));
		const contentKey = await crypto.subtle.importKey(
			'raw',
			contentKeyBuffer,
			'AES-CTR',
			false,
			['encrypt', 'decrypt']
		) as ContentKey;
		const payload = new Uint8Array(40);
		payload.fill(255, 0, 8);
		payload.set(contentKeyBuffer, 8);
		contentKeyBuffer.fill(0);
		const encPayload = new Uint8Array(await crypto.subtle.encrypt(
			{
				name: 'AES-CTR',
				counter: nonce,
				length: 32
			},
			vault.encKey,
			payload
		));		
		
		
		let encrypted = new Uint8Array(88);
		encrypted.set(nonce, 0);
		encrypted.set(encPayload, 16);
		const sig = new Uint8Array(await crypto.subtle.sign('HMAC', vault.macKey, encrypted.slice(0, 56)));
		encrypted.set(sig, 56);
		const chunkSize = 32768; // 32KiB
		for(let i = 0; i * chunkSize < content.byteLength; i++){
			const chunk = content.slice(i * chunkSize, (i + 1) * chunkSize);
			encrypted = concat(encrypted, await EncryptedFile.encryptChunk(vault, {
				contentKey: contentKey,
				nonce: nonce
			}, chunk, i));
		}
		
		let parentId: DirID;
		if(parent === null) parentId = '' as DirID;
		else if(typeof(parent) === 'string') parentId = parent;
		else parentId = await parent.getDirId();
		const encryptedDir = await vault.getDir(parentId);
		await vault.provider.createDir(encryptedDir, true);
		const fileName = await vault.encryptFileName(name, parentId);
		let fileDir;
		if(fileName.length > vault.vaultSettings.shorteningThreshold){
			const shortened = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(fileName));
			const shortDir = base64url.encode(new Uint8Array(shortened));
			fileDir = `${encryptedDir}/${shortDir}.c9s` as ItemPath;
			await vault.provider.writeFile(`${fileDir}/contents.c9r`, encrypted);
			await vault.provider.writeFile(`${fileDir}/name.c9r`, fileName);
		} else {
			fileDir = `${encryptedDir}/${fileName}.c9r` as ItemPath;
			await vault.provider.writeFile(fileDir, encrypted);
		}
		return new EncryptedFile(vault, fileName, fileDir, name, parentId, new Date());
	}

	constructor(vault: Vault, name: string, fullName: ItemPath, decryptedName: string, parentId: DirID, lastMod: Date){
		super(vault, name, fullName, decryptedName, parentId, lastMod);
		this.type = 'f';
	}

	/**
	 * Decrypts a file header
	 * @returns Content key that should be used for decrypting file content
	 * @throws InvalidSignatureError if HMAC verification fails
	 */
	async decryptHeader(data?: Uint8Array): Promise<Header>{
		if(!data) data = await this.readEncryptedFile();
		const payload = data.slice(0, 56);
		const nonce = data.slice(0, 16);
		const encContentKey = data.slice(16, 56);
		const hmac = data.slice(56, 88);

		const sig = new Uint8Array(await crypto.subtle.sign('HMAC', this.vault.macKey, payload));
		if(!isEqual(hmac, sig)) throw new InvalidSignatureError(DecryptionTarget.File);

		const exportedContentKey = new Uint8Array(await crypto.subtle.decrypt(
			{
				name: 'AES-CTR',
				counter: nonce,
				length: 32
			},
			this.vault.encKey,
			encContentKey
		));

		const contentKey = await crypto.subtle.importKey(
			'raw',
			exportedContentKey.slice(8),
			'AES-CTR',
			false,
			['encrypt', 'decrypt']
		) as ContentKey;

		return {
			contentKey: contentKey,
			nonce: nonce
		};
	}

	/**
	 * Read the encrypted file in binary
	 * @returns Uint8array of the encrypted file content
	 */
	async readEncryptedFile(){
		return await this.vault.provider.readFile(this.fullName);
	}

	/**
	 * Decrypt a chunk
	 * @param header Header object that contains file nonce and content key
	 * @param chunk Encrypted chunk
	 * @param chunkNumber The chunk number
	 * @returns Decrypted chunk in Uint8Array
	 * @throws InvalidSignatureError if the HMAC signature verification fails
	 */
	async decryptChunk(header: Header, chunk: Uint8Array, chunkNumber: number){
		const ciphertextSize = chunk.byteLength - 48; //Whole block - 16 byte nonce - 32 byte MAC
		const nonce = chunk.slice(0, 16);
		const data = chunk.slice(16, ciphertextSize + 16); //32784
		const hmac = chunk.slice(ciphertextSize + 16, chunk.byteLength); //32816
		const payload = new Uint8Array(40 + ciphertextSize);
		payload.set(header.nonce, 0);
		const cCount = new Uint8Array(BigUint64Array.from([BigInt(chunkNumber)]).buffer);
		cCount.reverse();
		payload.set(cCount, 16);
		payload.set(nonce, 24);
		payload.set(data, 40);
		const sig = new Uint8Array(await crypto.subtle.sign('HMAC', this.vault.macKey, payload));
		if(!isEqual(hmac, sig)) throw new InvalidSignatureError(DecryptionTarget.File);
		return new Uint8Array(await crypto.subtle.decrypt(
			{
				name: 'AES-CTR',
				counter: nonce,
				length: 32
			},
			header.contentKey,
			data
		));
	}

	/**
	 * Decrypt file content
	 * @returns Decrypted file content in Uint8Array
	 */
	async decryptContent(){
		const fileData = await this.readEncryptedFile();
		const header = await this.decryptHeader(fileData);
		const chunkSize = 32768 + 48; // 32KiB + 48 bytes
		let decrypted = new Uint8Array();
		for(let i = 0; i * chunkSize + 88 < fileData.byteLength; i++){
			const chunk = fileData.slice(i * chunkSize + 88, (i + 1) * chunkSize + 88);
			decrypted = concat(decrypted, await this.decryptChunk(header, chunk, i));
		}
		return decrypted;
	}

	/**
	 * Wrapper function for decryptContent that returns name and content
	 * @returns An object with two properties, title and content (Uint8Array)
	 */
	async decrypt(){
		return {
			title: this.decryptedName,
			content: await this.decryptContent()
		};
	}

	/**
	 * Wrapper function for decryptContent that returns name and content converted into string
	 * @returns An object with two properties, title and content (string)
	 */
	async decryptAsString(){
		return {
			title: this.decryptedName,
			content: new TextDecoder().decode(await this.decryptContent())
		};
	}

	/**
	 * Delete this file. All details within this object will become invalid after this function is called.
	 */
	async deleteFile(){
		await this.vault.deleteFile(this);
	}
}

function isEqual(a: Uint8Array, b: Uint8Array){
	if(a.byteLength !== b.byteLength) return false;
	if(a.every((v, i) => v === b[i])) return true;
	else return false;
}

function concat(a: Uint8Array, b: Uint8Array){
	const ret = new Uint8Array(a.length + b.length);
	ret.set(a, 0);
	ret.set(b, a.length);
	return ret;
}