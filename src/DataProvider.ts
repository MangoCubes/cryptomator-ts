import { Item } from "./types";

export type DataProvider = {
	readFileString: (path: string) => string;
	listItems: (path: string) => Item[];
}