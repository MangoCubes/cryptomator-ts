import { beforeAll, describe, expect, test } from '@jest/globals';
import path from "path";
import { Vault } from '../src/Vault';
import { LocalStorageProvider } from '../src/providers/LocalStorageProvider';
import { TargetFS } from './TargetFS';
import { DirID } from '../src/types';
import { EncryptedDir } from '../src/encrypted/EncryptedDir';

/**
 * Gets all directories of the vault
 * @param vault Target vault
 * @returns All directories in that vault
 */
async function getAllDirs(vault: Vault){
	const dirs: {[dirId: DirID]: EncryptedDir} = {};
	dirs['' as DirID] = await vault.getRootDir()
	const dirsToExplore: DirID[] = ['' as DirID];
	while(dirsToExplore.length){
		const target = dirsToExplore.shift()!;
		const items = await vault.listItems(target);
		for(const i of items) if(i.type === 'd'){
			dirs[await i.getDirId()] = i;
			dirsToExplore.push(await i.getDirId());
		}
	}
	return dirs;
}

describe('Test modifying the vault', () => {
	const provider = new LocalStorageProvider();
	const dir = path.resolve(__dirname, 'modifyTest');
	beforeAll(async () => {
		const testVaults = await provider.listItems(dir);
		for(const v of testVaults) await provider.removeDir(v.fullName);
	});
	test('Create a vault, and move folders around', async () => {
		const sample = await TargetFS.create(provider, dir, 1, 32);
		const f = async () => {
			const allFolders = await getAllDirs(sample.vault);
			for(const k in allFolders){
				if(k === '') continue;
				const folder = allFolders[k as DirID];
				const action = Math.floor(Math.random() * 2);
				if(action){
					const parent = sample.randomMove(await folder.getDirId());
					await folder.move(parent);
				}
			}
			return await sample.verify();
		}
		await expect(f()).resolves.toBe('Identical');
	});
	test('Create a vault, and rename files and folders', async () => {
		const sample = await TargetFS.create(provider, dir, 2, 32);
		const f = async () => {
			const allFolders = await getAllDirs(sample.vault);
			for(const k in allFolders){
				if(k === '') continue;
				const folder = allFolders[k as DirID];
				const renames = sample.randomRename(await folder.getDirId(), 3);
				const items = await sample.vault.listItems(k as DirID);
				for(const r of renames){
					const item = items.find(i => i.decryptedName === r.from);
					if(!item) throw new Error('Item with corresponding name not found.');
					await item.rename(r.to);
				}
			}
			return await sample.verify();
		}
		await expect(f()).resolves.toBe('Identical');
	});
	test('Create a vault, and rename files and folders with long names', async () => {
		const sample = await TargetFS.create(provider, dir, 3, 777);
		const f = async () => {
			const allFolders = await getAllDirs(sample.vault);
			for(const k in allFolders){
				if(k === '') continue;
				const folder = allFolders[k as DirID];
				const renames = sample.randomRename(await folder.getDirId(), 3);
				const items = await sample.vault.listItems(k as DirID);
				for(const r of renames){
					const item = items.find(i => i.decryptedName === r.from);
					if(!item) throw new Error('Item with corresponding name not found.');
					await item.rename(r.to);
				}
			}
			return await sample.verify();
		}
		await expect(f()).resolves.toBe('Identical');
	});
});