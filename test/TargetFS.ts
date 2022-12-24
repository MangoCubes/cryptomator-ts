import { EncryptedFile } from "../src/encrypted/EncryptedFile";
import { LocalStorageProvider } from "../src/providers/LocalStorageProvider";
import { DirID } from "../src/types";
import { Vault } from "../src/Vault";
import crypto from 'node:crypto';

type SimpleFile = {
	type: 'f';
	name: string;
};

type SimpleDir = {
	type: 'd';
	name: string;
	id: DirID;
};

type SimpleItem = SimpleFile | SimpleDir;

type DirInfo = {
	children: SimpleItem[];
	parent: DirID | null;
}

function makeId(len: number) {
	let result = '';
    const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for(let i = 0; i < len; i++) result += c[Math.floor(Math.random() * c.length)];
    return result;
}
/**
 * Simple vault generator, and simplified mock of it attached to it
 */
export class TargetFS{

	private constructor(public vault: Vault, public tree: {[key: DirID]: DirInfo}){}

	/**
	 * Creates random files and folders
	 */

	static async create(provider: LocalStorageProvider, dir: string, id: number, len: number){
		const v = await Vault.create(provider, dir, '12341234', {
			create:{
				name: `encTest${id}`
			}
		});
		const path: DirID[] = [];
		const tree: {[key: string]: DirInfo} = {'': {
			children: [],
			parent: null
		}};
		for(let i = 0; i < 1000; i++){
			const action = Math.floor(Math.random() * (path.length === 0 ? 2 : 3));
			const last = path.length === 0 ? '' as DirID : path[path.length - 1];
			/**
			 * 0: Create a file in the current directory. Name is a random UUID, and its content is SHA-256 of the decrypted name.
			 * 1: Create a directory, and go into it. Name is a randomly generated UUID.
			 * 2: Go up a directory. Unavailable if the current directory is root.
			 */
			if(action === 0){
				const name = makeId(len);
				const content = crypto.createHash('sha256').update(name).digest();
				await EncryptedFile.encrypt(v, name, last, content);
				tree[last].children.push({type: 'f', name: name});
			} else if(action === 1){
				const name = makeId(len);
				const dir = await v.createDirectory(name, last);
				const dirId = await dir.getDirId();
				path.push(dirId);
				tree[last].children.push({type: 'd', name: name, id: dirId});
				tree[dirId] = {
					children: [],
					parent: last
				};
			} else if(action === 2) path.pop();
		}
		return new TargetFS(v, tree);
	}

	async verify(){
		const folders = ['' as DirID];
		while(folders.length){
			const current = folders.pop()!;
			const vaultItems = await this.vault.listItems(current);
			const mockItems = this.tree[current];
			if(vaultItems.length !== mockItems.children.length) throw new Error(`The following directory contains differing number of items: "${current}"`);
			const children = [...mockItems.children];
			vaultItems.sort((a, b) => a.decryptedName.localeCompare(b.decryptedName));
			children.sort((a, b) => a.name.localeCompare(b.name));
			for(let i = 0; i < vaultItems.length; i++){
				const a = vaultItems[i];
				const b = children[i];
				if(b.name !== a.decryptedName || b.type !== a.type) throw new Error(`The following have different name or type: ${a}, ${b}`);
				if(a.type === 'd' && b.type === 'd'){
					const dirA = await a.getDirId();
					const dirB = b.id;
					if(dirA !== dirB) throw new Error(`The following have different directory ID: ${a} (${dirA}), ${b} (${dirB})`);
					folders.push(dirA);
				}
				if(a.type === 'f'){
					const content = crypto.createHash('sha256').update(a.decryptedName).digest();
					const decrypted = await a.decrypt();
					if(Buffer.compare(content, decrypted.content) !== 0) throw new Error(`The following have corrupt contents: ${a}`);
				}
			}
		}
		// for(const k in this.tree) if(this.tree[k as DirID].length !== 0) return this.tree[k as DirID];
		return 'Identical' as const;
	}

	moveFolder(target: DirID, under: DirID){
		//Locate parent folder of the target
		const parent = this.tree[target].parent;
		//Make sure the parent folder actually exists
		if(parent === null) throw new Error('Trying to move root directory (Note that folders IN root directory will have parent ID of "".)');
		//Get sibling folders of the target folder
		const children = this.tree[parent];
		//Find the target folder
		const index = children.children.findIndex(v => v.type === 'd' && v.id === target);
		//If it does not exist, throw error
		if(index === -1) throw new Error('Target folder does not exist under parent.');
		//Locate the target folder info in the parent folder
		const targetFolder = children.children.splice(index, 1)[0] as SimpleDir;
		//Replace the original data in the parent folder with the one with the target folder info removed
		this.tree[parent] = children;
		//Add the removed data into the new parent folder
		this.tree[under].children.push(targetFolder);
		//Update the parent folder data of the target folder
		this.tree[targetFolder.id].parent = under;
	}

	delFolder(parent: DirID, id: DirID){
		const folders = [id];
		while(folders.length){
			const current = folders.pop() as DirID;
			const items = this.tree[current].children;
			for(const i of items) if(i.type === 'd') folders.push(i.id);
			delete this.tree[current];
		}
		for(let i = 0; i < this.tree[parent].children.length; i++){
			const dir = this.tree[parent].children[i];
			if(dir.type === 'd' && dir.id === id) this.tree[parent].children.splice(i, 1);
		}
		return null;
	}

	/**
	 * Find a replacement parent
	 * @param target The foldet that should be moved
	 * @returns The ID of the folder it was moved into
	 */
	randomMove(target: DirID): DirID{
		if(target === '') throw new Error('Cannot move root folder.');
		// Cannot be null, but can be "" (representing that this folder will go under root).
		let parent = this.tree[target].parent!;
		const action = Math.floor(Math.random() * 2);
		/**
		 * 0: Destination parent folder becomes the one up one folder. Will be no-op if the current folder is already root.
		 * 1: Destination parent folder becomes a random children folder. Will be no-op if none found, or the chosen folder is the target folder.
		 */
		// Only DirID of "" has parent directory of null.
		if(action === 0 && parent !== '') parent = this.tree[parent].parent!;
		else if(action === 1){
			const folders = this.tree[parent].children.filter(v => v.type === 'd') as SimpleDir[];
			const randIndex = Math.floor(Math.random() * folders.length);
			const cand = folders[randIndex].id;
			if(cand !== target) parent = cand;
		}
		this.moveFolder(target, parent);
		return parent;
	}
}