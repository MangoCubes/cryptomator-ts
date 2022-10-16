import { Item } from "./types";

export enum DecryptionTarget {
	Filename,
	Item,
	Vault
}

export class InvalidVaultError extends Error{
	
}

type DecErrMap = {
	[DecryptionTarget.Filename]: Item;
	[DecryptionTarget.Item]: Item;
	[DecryptionTarget.Vault]: null;
};

export class DecryptionError<T extends DecryptionTarget> extends Error{
	constructor(public type: T, public target: DecErrMap[T]){
		super();
	}
}

