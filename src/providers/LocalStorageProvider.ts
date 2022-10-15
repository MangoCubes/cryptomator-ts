import { DataProvider } from "../DataProvider";
import { Item } from "../types";
import { promises as fs } from "fs";

export class LocalStorageProvider implements DataProvider{
	async readFileString (path: string): Promise<string>{
		return await fs.readFile(path, 'utf-8');
	}
	async listItems (path: string): Promise<Item[]>{
		throw new Error('Not implemented');
	};
}