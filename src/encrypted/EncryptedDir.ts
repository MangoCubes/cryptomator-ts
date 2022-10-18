import { Directory, DirID, ItemPath } from "../types";
import { Vault } from "../Vault";
import { EncryptedItemBase } from "./EncryptedItemBase";

export class EncryptedDir extends EncryptedItemBase implements Directory{
	type: 'd';

	constructor(vault: Vault, name: string, fullName: ItemPath, decryptedName: string, dirId: DirID, lastMod: Date){
		super(vault, name, fullName, decryptedName, dirId, lastMod);
		this.type = 'd';
	}
}