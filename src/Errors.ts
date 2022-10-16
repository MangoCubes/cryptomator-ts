export enum DecryptTarget {
	Filename,
	File,
	Vault
}

export class InvalidVaultError extends Error{
	
}

export class DecryptionError extends Error{
	target: DecryptTarget;
	constructor(target: DecryptTarget){
		super();
		this.target = target;
	}
}