import { Directory, DirID, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedItemBase } from "./EncryptedItemBase";

export class EncryptedDir extends EncryptedItemBase implements Directory{
	type: 'd';
	dirId: null | DirID;

	/**
	 * Construct a directory object. Use this instead of default constructor as this provides additional options.
	 * @param vault Vault object that can decrypt this directory
	 * @param name Encrypted directory name
	 * @param fullName *Encrypted* directory that corresponds to this object
	 * @param decryptedName Name of the folder after decryption
	 * @param parent Directory ID of the parent folder
	 * @param lastMod Last modification date
	 * @param options.cacheDirId If true, the ID of the directory will be queried, and cached into the object.
	 * @returns EncryptedDir object
	 */
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

	private constructor(vault: Vault, name: string, fullName: ItemPath, decryptedName: string, parent: DirID, lastMod: Date, dirId: DirID | null){
		super(vault, name, fullName, decryptedName, parent, lastMod);
		this.dirId = dirId;
		this.type = 'd';
	}

	/**
	 * Get the ID of this directory
	 * @returns ID of this directory
	 * 
	 * Calling this method will cache ID if it is not already.
	 */
	async getDirId(){
		if(!this.dirId) this.dirId = await this.vault.provider.readFileString(this.fullName + '/dir.c9r') as DirID;
		return this.dirId;
	}

	/**
	 * List directories and files in this directory. Most likely easier to use than using vault's listItems method directly.
	 * @returns Items under this directory
	 */
	async listItems(){
		return await this.vault.listItems(await this.getDirId());
	}
}