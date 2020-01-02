# twofat
## Two Factor Authentication Tool
### Manage a 2FA database from the commandline
* **v0.1.2**
* Repo [gitlab.com/pepa/twofat](https://gitlab.com/pepa65/twofat)
* After [github.com/slandx/tfat](https://github.com/slandx/tfat)

## Features
- Save data with AES-GCM encrypt.
- Save data with password, generate random password if none provided.
- Auto-refreshing displayed codes.
- Add code to clipboard.

## Build
```shell
# While in the repo root directory:
go build
```

## Usage
`twofat help`:
```
NAME:
   Two Factor Authentication Tool - Manage a 2FA database from the commandline

USAGE:
   twofat [global options] command [command options] [arguments...]

VERSION:
   0.1.2

COMMANDS:
   show      Show codes for all entries
   add       Add a new entry NAME with SECRET
   secret    Show secret of entry NAME
   clip      Put code of entry NAME onto the clipboard
   delete    Delete entry NAME
   password  Change password
   import    Import entries 'NAME,SECRET,CODELENGTH' from CSV file
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     Show this help
   --version, -V  Print version
```
