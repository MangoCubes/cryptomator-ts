export type Item = {
	type: 'f' | 'd';
	name: string;
	fullName: ItemPath;
	lastMod: number; //Timestamp
	size: number;
}

export type ItemPath = string & {__type: 'ItemPath'};