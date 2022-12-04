import { Item } from "./types";

export type ProgressCallback = (current: number, total: number) => void;

export type DataProvider = {
	readFileString: (path: string, progress?: ProgressCallback) => Promise<string>;
	listItems: (path: string) => Promise<Item[]>;
	readFile: (path: string, progress?: ProgressCallback) => Promise<Uint8Array>;
	writeFile: (path: string, content: Uint8Array | string, progress?: ProgressCallback) => Promise<void>;
	createDir: (path: string, recursive?: boolean) => Promise<void>;
	removeFile: (path: string) => Promise<void>;
	/**
	 * Should be able to delete recursively
	 */
	removeDir: (path: string) => Promise<void>;
}