import { Item } from "./types";

export type DataProvider = {
	readFileString: (path: string) => Promise<string>;
	listItems: (path: string) => Promise<Item[]>;
	readFile: (path: string) => Promise<Uint8Array>;
	writeFile: (path: string, content: Uint8Array) => Promise<void>;
	writeFileString: (path: string, content: string) => Promise<void>;
	createDir: (path: string, recursive?: boolean) => Promise<void>;
}