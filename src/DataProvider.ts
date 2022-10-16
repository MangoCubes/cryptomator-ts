import { Item } from "./types";

export type DataProvider = {
	readFileString: (path: string) => Promise<string>;
	listItems: (path: string) => Promise<string[]>;
	readFile: (path: string) => Promise<Uint8Array>;
}