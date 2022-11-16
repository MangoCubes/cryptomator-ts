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
		public parentId: DirID,
		public lastMod: Date,
		public shortened: boolean
	){

	}
}

export type EncryptedItem = EncryptedFile | EncryptedDir;