import { base64url } from "jose";
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

	/**
	 * Rename this item.
	 * @param to: Name this item should be changed to
	 */
	async rename(to: string){
		if(this.parentId === null) throw new Error('Cannot rename the root folder.');
		const encryptedName = await this.vault.encryptFileName(to, this.parentId);
		const short = encryptedName.length >= this.vault.vaultSettings.shorteningThreshold;
		const parentDir = await this.vault.getDir(this.parentId);
		if(short){ // If new name needs to be shortened
			const shortened = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(encryptedName));
			const shortDir = base64url.encode(new Uint8Array(shortened));
			const fullDir = `${parentDir}/${shortDir}.c9s` as ItemPath;
			if(this.shortened){
				const fileNameFile = `${this.fullName}/name.c9s`;
				await this.vault.provider.writeFile(fileNameFile, encryptedName);
				await this.vault.provider.rename(this.fullName, fullDir);
			} else {
				// TODO
			}
		} else {
			if(this.shortened){
				// TODO
			} else { // If the old name was not shortened
				const parentDir = this.fullName.split('/');
				parentDir[parentDir.length - 1] = encryptedName + '.c9r';
				await this.vault.provider.rename(this.fullName, parentDir.join('/'));
			}
		}
	}
}

export type EncryptedItem = EncryptedFile | EncryptedDir;