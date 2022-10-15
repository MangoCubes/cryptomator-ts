import { Item } from "./types";

export type DataProvider = {
	readFileString: (path: string) => Promise<string>;
	listItems: (path: string) => Promise<Item[]>;
}