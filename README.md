# cryptomator-ts (UNOFFICIAL)
Read and write files into a Cryptomator vault using this library

**This project is highly experimental. Although there are some tests written to alleviate malfunctioning, it most likely does not cover all edge cases. Do not use it for mission-critical data.**

## Features
 - [x] Read contents of the vault
 - [x] Verify `vault.cryptomator` integrity
 - [x] Create encrypted files and directory
 - [x] Create a new vault
 - [x] Filename shortening
 - [ ] Symlinks
 - [ ] Backup directory ID
 - [x] Progress callbacks (A callback that is called every time part of download/encryption/etc is done)
