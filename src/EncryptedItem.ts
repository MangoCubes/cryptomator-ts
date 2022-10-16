import { DirID } from "./types";

export class EncryptedItem{
	constructor(public encName: string, public decryptedName: string, public dirId: DirID, public type: 'd' | 'f'){

	}
}