import { DirID, Item, ItemPath } from "./types";

export class EncryptedItem implements Item{
	constructor(
		public encName: string,
		public name: string,
		public dirId: DirID,
		public type: 'd' | 'f',
		public lastMod: Date,
		public size: number,
		public fullName: ItemPath
	){

	}	
}