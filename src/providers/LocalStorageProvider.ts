import { DataProvider } from "../DataProvider";
import { Item, ItemPath } from "../types";
import { promises as fs, existsSync} from "fs";
import * as p from "path";

export class LocalStorageProvider implements DataProvider{
	async rename (path: string, newPath: string): Promise<void>{
		await fs.rename(path, newPath);
	}
	async exists (path: string){
		return existsSync(path);
	}
	async removeFile(path: string): Promise<void>{
		await fs.rm(path);
	}
	
	async removeDir(path: string): Promise<void>{
		await fs.rm(path, {recursive: true});
	}
	async createDir(path: string, recursive?: boolean | undefined): Promise<void>{
		await fs.mkdir(path, {recursive: recursive});
	}
	async readFile(path: string): Promise<Uint8Array>{
		return new Uint8Array(await fs.readFile(path));
	}

	async readFileString (path: string): Promise<string>{
		return await fs.readFile(path, 'utf-8');
	}

	async listItems (path: string): Promise<Item[]>{
		const names = await fs.readdir(path);
		const items: Item[] = [];
		for (const name of names){
			const fullName = p.join(path, name);
			const stat = await fs.stat(fullName);
			items.push({
				type: stat.isDirectory() ? 'd' : 'f',
				name: name,
				fullName: fullName as ItemPath,
				lastMod: stat.mtime
			});
		}
		return items;
	}

	async writeFile(path: string, data: Uint8Array | string){
		await fs.writeFile(path, data);
	}

	async move (path: string, newPath: string){
		await fs.rename(path, newPath);
	}
}