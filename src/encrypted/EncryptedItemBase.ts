import { DirID, ItemBase, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedDir } from "./EncryptedDir";
import { EncryptedFile } from "./EncryptedFile";

export abstract class EncryptedItemBase implements ItemBase{
	constructor(
		public vault: Vault,
		public name: string,
		public fullName: ItemPath,
		public decryptedName: string,
		public parentId: DirID | null,
		public lastMod: Date,
		public shortened: boolean
	){

	}
	async rename(to: string){
		if(this.parentId === null) throw new Error('Cannot rename the root folder.');
		const encryptedName = await this.vault.encryptFileName(to, this.parentId);
		const parentDir = this.fullName.split('/');
		parentDir[parentDir.length - 1] = encryptedName + '.c9r';
		await this.vault.provider.rename(this.fullName, parentDir.join('/'));
	}
}

export type EncryptedItem = EncryptedFile | EncryptedDir;