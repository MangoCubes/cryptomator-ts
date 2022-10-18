import { Directory, DirID, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedItemBase } from "./EncryptedItemBase";

export class EncryptedDir extends EncryptedItemBase implements Directory{
	type: 'd';

	constructor(vault: Vault, name: string, fullName: ItemPath, decryptedName: string, dirId: DirID, lastMod: Date){
		super(vault, name, fullName, decryptedName, dirId, lastMod);
		this.type = 'd';
	}

	/**
	 * Get the ID of this directory
	 * @returns ID of this directory
	 * 
	 * Potential changes:
	 * Cache this ID in this class
	 * Add an option to get ID upon creating this object by using static async constructor
	 */
	async getDirId(){
		return await this.vault.provider.readFileString(this.fullName + '/dir.c9r') as DirID;
	}
}