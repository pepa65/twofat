# twofat
## Two Factor Authentication Tool
### Manage a 2FA database from the commandline
* **v0.2.0**
* Repo [gitlab.com/pepa/twofat](https://github.com/pepa65/twofat)
* After [github.com/slandx/tfat](https://github.com/slandx/tfat)

## Features
* Data saved with AES-GCM encrypt in ~/.<binaryname>.enc
* Display names matching regex.
* Displayed codes auto-refresh.
* Code to clipboard.
* Import entries from CSV.

## Build
```shell
# While in the repo root directory:
go get -u github.com/pepa65/twofat
```

## Usage
`twofat help`:
```
NAME:
   twofat - Two Factor Authentication Tool

USAGE:
   twofat [global options] command [command options] [arguments...]

VERSION:
   0.2.0

DESCRIPTION:
   Manage a 2FA database from the commandline

AUTHOR:
   github.com/pepa65/twofat <pepa65@passchier.net>

COMMANDS:
   show, view, list, ls  Show codes for all entries [that match REGEX]
   add, insert, entry    Add a new entry NAME with SECRET
   secret, reveal        Show secret of entry NAME
   clip, copy, cp        Put code of entry NAME onto the clipboard
   delete, remove, rm    Delete entry NAME
   password, passwd, pw  Change password
   import, csv           Import entries 'NAME,SECRET,CODELENGTH' from CSVFILE
   help, h               Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h         Show this help, or use after a command for command help
   --version, -V, -v  Print version
```