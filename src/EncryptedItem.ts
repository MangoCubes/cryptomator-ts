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