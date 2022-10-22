export type ItemBase = {
	name: string;
	fullName: ItemPath;
	lastMod: Date;
}

export type Directory = ItemBase & {
	type: 'd';
}

export type File = ItemBase & {
	type: 'f';
}

export type Item = File | Directory;

export type ItemPath = string & {__type: 'ItemPath'};
export type Base64Str = string & {__type: 'Base64Str'};
export type DirID = string & {__type: 'DirID'};

export type EncryptionKey = CryptoKey & {__type: 'EncryptionKey'};
export type MACKey = CryptoKey & {__type: 'MACKey'};
export type ContentKey = CryptoKey & {__type: 'ContentKey'}