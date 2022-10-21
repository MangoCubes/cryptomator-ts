import { DecryptionTarget, InvalidSignatureError } from "../Errors";
import { ContentKey, DirID, File, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedItemBase } from "./EncryptedItemBase";

type Header = {
	contentKey: ContentKey;
	nonce: Uint8Array;
}

export class EncryptedFile extends EncryptedItemBase implements File{
	type: 'f';
	size: number;

	constructor(vault: Vault, name: string, fullName: ItemPath, decryptedName: string, parentId: DirID, lastMod: Date, size: number){
		super(vault, name, fullName, decryptedName, parentId, lastMod);
		this.size = size;
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

	async readEncryptedFile(){
		return await this.vault.provider.readFile(this.fullName);
	}

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

	async decrypt(){
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