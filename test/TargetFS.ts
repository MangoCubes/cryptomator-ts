import { EncryptedFile } from "../src/encrypted/EncryptedFile";
import { LocalStorageProvider } from "../src/providers/LocalStorageProvider";
import { DirID } from "../src/types";
import { Vault } from "../src/Vault";
import crypto from 'node:crypto';

type SimpleItem = {
	type: 'f';
	name: string;
} | {
	type: 'd';
	name: string;
	id: DirID;
}

function makeId(len: number) {
	let result = '';
    const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for(let i = 0; i < len; i++) result += c[Math.floor(Math.random() * c.length)];
    return result;
}

export class TargetFS{

	private constructor(public vault: Vault, public tree: {[key: DirID]: SimpleItem[]}){}

	/**
	 * Creates random files and folders
	 * 0: Create a file in the current directory. Name is a random UUID, and its content is SHA-256 of the decrypted name.
	 * 1: Create a directory, and go into it. Name is a randomly generated UUID.
	 * 2: Go up a directory. Unavailable if the current directory is root.
	 */

	static async create(provider: LocalStorageProvider, dir: string, id: number, len: number){
		const v = await Vault.create(provider, dir, '12341234', {
			name: `encTest${id}`
		});
		const path: DirID[] = [];
		const tree: {[key: string]: SimpleItem[]} = {'': []};
		for(let i = 0; i < 1000; i++){
			const action = Math.floor(Math.random() * (path.length === 0 ? 2 : 3));
			const last = path.length === 0 ? '' as DirID : path[path.length - 1];
			if(action === 0){
				const name = makeId(len);
				const content = crypto.createHash('sha256').update(name).digest();
				await EncryptedFile.encrypt(v, name, last, content);
				if(tree[last]) tree[last].push({type: 'f', name: name});
				else tree[last] = [{type: 'f', name: name}];
			} else if(action === 1){
				const name = makeId(len);
				const dir = await v.createDirectory(name, last);
				const dirId = await dir.getDirId();
				path.push(dirId);
				tree[last].push({type: 'd', name: name, id: dirId});
				tree[dirId] = [];
			} else if(action === 2) path.pop();
		}
		return new TargetFS(v, tree);
	}

	async verify(){
		const folders = ['' as DirID];
		while(folders.length){
			const current = folders.pop() as DirID;
			const items = await this.vault.listItems(current);
			for(const item of items){
				if(item.type === 'd') folders.push(await item.getDirId());
				const index = this.tree[item.parentId].findIndex(i => i.name === item.decryptedName && i.type === item.type);
				if(index === -1) return item;
				else {
					if(item.type === 'f'){
						const content = crypto.createHash('sha256').update(this.tree[item.parentId][index].name).digest();
						const decrypted = await item.decrypt();
						if(Buffer.compare(content, decrypted.content) !== 0) return item;
					}
					this.tree[item.parentId].splice(index, 1);
				}
			}
		}
		for(const k in this.tree) if(this.tree[k as DirID].length !== 0) return this.tree[k as DirID];
		return null;
	}

	delFolder(parent: DirID, id: DirID){
		const folders = [id];
		while(folders.length){
			const current = folders.pop() as DirID;
			const items = this.tree[current];
			for(const i of items) if(i.type === 'd') folders.push(i.id);
			delete this.tree[current];
		}
		for(let i = 0; i < this.tree[parent].length; i++){
			const dir = this.tree[parent][i];
			if(dir.type === 'd' && dir.id === id) this.tree[parent].splice(i, 1);
		}
		return null;
	}
}