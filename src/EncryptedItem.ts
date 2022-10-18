import { InvalidSignatureError, DecryptionTarget } from "./Errors";
import { DirID, Item, ItemPath } from "./types";
import { Vault } from "./Vault";

export class EncryptedItem implements Item{
	constructor(
		public vault: Vault,
		public encName: string,
		public fullName: ItemPath, //Encrypted path
		public name: string,
		public dirId: DirID,
		public type: 'd' | 'f',
		public lastMod: Date,
		public size: number,
	){

	}

	async decryptHeader(){
		const data = await this.vault.provider.readFile(this.fullName);
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
		);

		return contentKey;
	}
}

function isEqual(a: Uint8Array, b: Uint8Array){
	if(a.byteLength !== b.byteLength) return false;
	if(a.every((v, i) => v === b[i])) return true;
	else return false;
}