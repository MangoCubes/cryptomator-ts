import { Item } from "./types";

export enum DecryptionTarget {
	ItemName,
	File,
	Directory,
	Vault
}

export class InvalidSignatureError<T extends DecryptionTarget.File | DecryptionTarget.Vault> extends Error{
	constructor(public type: T){
		super();
	}
}

type DecErrMap = {
	[DecryptionTarget.ItemName]: Item;
	[DecryptionTarget.File]: Item & {type: 'f'};
	[DecryptionTarget.Vault]: null;
};
/**
 * Indicates wrong password
 */
export class DecryptionError<T extends Exclude<DecryptionTarget, DecryptionTarget.Directory>> extends Error{
	constructor(public type: T, public target: DecErrMap[T]){
		super();
	}
}

export class ExistsError extends Error{
	constructor(public which: string){
		super();
	}
}