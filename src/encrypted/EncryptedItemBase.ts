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
		/**
		 * If shortened:
		 * this.name contains the content of name.c9s file
		 * this.fullName points to the directory that contains the name.c9s file
		 * 
		 * If not:
		 * this.fullName points to the directory/file this object corresponds to
		 * this.name is the last part of this.fullName
		 */
		public shortened: boolean
	){

	}

	/**
	 * Move an item under another directory
	 * @param dir Directory this folder should be moved under
	 */
	async move(dir: EncryptedDir){
		const parentId = await dir.getDirId();
		const parentDir = await this.vault.getDir(parentId);
		const fileName = await this.vault.encryptFileName(this.decryptedName, parentId);
		if(fileName.length > this.vault.vaultSettings.shorteningThreshold){
			const shortened = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(fileName));
			const shortDir = base64url.encode(new Uint8Array(shortened));
			const fileDir = `${parentDir}/${shortDir}.c9s` as ItemPath;
			await this.vault.provider.move(this.fullName, fileDir);
			await this.vault.provider.writeFile(`${fileDir}/name.c9s`, fileName);
			
		} else {
			const fileDir = `${parentDir}/${fileName}.c9r` as ItemPath;
			await this.vault.provider.move(this.fullName, fileDir);
		}
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
				this.fullName = fullDir;
			} else {
				// TODO
			}
		} else {
			if(this.shortened){
				// TODO
			} else { // If the old name was not shortened
				const newName = `${parentDir}/${encryptedName}.c9r` as ItemPath;
				await this.vault.provider.rename(this.fullName, newName);
				this.fullName = newName;
			}
		}
		this.name = encryptedName;
		this.decryptedName = to;
	}
}

export type EncryptedItem = EncryptedFile | EncryptedDir;