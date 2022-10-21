import { Directory, DirID, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedItemBase } from "./EncryptedItemBase";

export class EncryptedDir extends EncryptedItemBase implements Directory{
	type: 'd';
	dirId: null | DirID;

	static async open(
		vault: Vault,
		name: string,
		fullName: ItemPath,
		decryptedName: string,
		parent: DirID,
		lastMod: Date,
		options?: {
			cacheDirId?: boolean
		}
	){
		let dirId: DirID | null = null;
		if(options?.cacheDirId) dirId = await vault.provider.readFileString(fullName + '/dir.c9r') as DirID;
		return new EncryptedDir(vault, name, fullName, decryptedName, parent, lastMod, dirId);
	}

	constructor(vault: Vault, name: string, fullName: ItemPath, decryptedName: string, parent: DirID, lastMod: Date, dirId: DirID | null){
		super(vault, name, fullName, decryptedName, parent, lastMod);
		this.dirId = dirId;
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
		if(!this.dirId) this.dirId = await this.vault.provider.readFileString(this.fullName + '/dir.c9r') as DirID;
		return this.dirId;
	}

	async listItems(){
		return await this.vault.listItems(await this.getDirId());
	}
}