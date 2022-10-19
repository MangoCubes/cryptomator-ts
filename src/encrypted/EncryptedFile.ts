import { DecryptionTarget, InvalidSignatureError } from "../Errors";
import { ContentKey, DirID, File, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedItemBase } from "./EncryptedItemBase";

type Header = {
	contentKey: ContentKey;
	nonce: Uint8Array;
}

const ciphertextSize = 32768;
const chunkSize = ciphertextSize + 48;

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
		// const allOne = data.slice(16, 24);
		const encContentKey = data.slice(24, 56);
		const hmac = data.slice(56, 88);

		const sig = new Uint8Array(await crypto.subtle.sign('HMAC', this.vault.macKey, payload));
		if(!isEqual(hmac, sig)) throw new InvalidSignatureError(DecryptionTarget.File);

		const exportedContentKey = await crypto.subtle.decrypt(
			{
				name: 'AES-CTR',
				counter: nonce,
				length: 64
			},
			this.vault.encKey,
			encContentKey
		);

		const contentKey = await crypto.subtle.importKey(
			'raw',
			exportedContentKey,
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
		const nonce = chunk.slice(0, 16);
		const data = chunk.slice(16, ciphertextSize + 16);
		const hmac = chunk.slice(ciphertextSize + 16, chunkSize);
		const payload = new Uint8Array(40 + ciphertextSize);
		payload.set(header.nonce, 0);
		const cCount = new Uint8Array(BigUint64Array.from([BigInt(chunkNumber)]).buffer);
		cCount.reverse();
		payload.set(cCount, 16);
		payload.set(nonce, 24);
		payload.set(data, 40);
		const sig = new Uint8Array(await crypto.subtle.sign('HMAC', this.vault.macKey, payload));
		if(!isEqual(hmac, sig))
			throw new InvalidSignatureError(DecryptionTarget.File);
		// const content = await crypto.subtle.decrypt(
		// 	{
		// 		name: 'AES-CTR',
		// 		counter: nonce,
		// 		length: 64
		// 	},
		// 	this.vault.encKey,
		// 	encContentKey
		// );
	}

	async decrypt(){
		const fileData = await this.readEncryptedFile();
		const header = await this.decryptHeader(fileData);
		for(let i = 0; i * chunkSize + 88 < fileData.byteLength; i++){
			const chunk = fileData.slice(i * chunkSize + 88, (i + 1) * chunkSize + 88);
			await this.decryptChunk(header, chunk, i);
		}
	}
}

function isEqual(a: Uint8Array, b: Uint8Array){
	if(a.byteLength !== b.byteLength) return false;
	if(a.every((v, i) => v === b[i])) return true;
	else return false;
}