# twofat
## Manage a 2FA database from the commandline
* **v0.4.0**
* Repo: [github.com/pepa65/twofat](https://github.com/pepa65/twofat)
* After: [github.com/slandx/tfat](https://github.com/slandx/tfat)
* Contact: pepa65 <pepa65@passchier.net>
* Install: `wget -qO- gobinaries.com/pepa65/twofat |sh`

## Features
* Data saved with AES-GCM encrypt in ~/.twofat.enc, password changeable.
* Display codes of names matching regex, which auto-refresh.
* Add, rename, delete entry, reveal secret, copy code to clipboard.
* Import entries from CSV.

## Build
```shell
# While in the repo root directory:
go build

# Or anywhere:
go get -u github.com/pepa65/twofat

# Smaller binary:
go build -ldflags="-s -w"

# More extreme shrinking:
upx --brute twofat*

# Build for various architectures:
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o twofat
GOOS=linux GOARCH=arm go build -ldflags="-s -w" -o twofat_pi
GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o twofat_bsd
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o twofat_osx
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o twofat.exe
```

## Usage
```
twofat v0.4.0 - Manage a 2FA database from the commandline
* Repo:      github.com/pepa65/twofat <pepa65@passchier.net>
* Database:  ~/.twofat.enc
* Usage:     twofat [COMMAND]
COMMAND:
  [ show | view | list | ls ]  [REGEX]
      Show all Codes [with Names matching REGEX] (the command is optional).
  add | insert | entry  NAME  [-7|-8]  [-f|--force]  [SECRET]
      Add a new entry NAME with SECRET (queried when not given).
      When -7 or -8 are given, Code length is 7 or 8, otherwise it is 6.
      If -f/--force is given, no confirmation is asked when NAME exists.
  totp | temp  [-7|-8]  [SECRET]
      Show the Code for SECRET (queried when not given).
      When -7 or -8 are given, Code length is 7 or 8, otherwise it is 6.
      (The database is not queried nor written to.)
  delete | remove | rm  NAME  [-f|--force]
      Delete entry NAME. If -f/--force is given, no confirmation is asked.
  rename | move | mv  NAME  NEWNAME       Rename entry from NAME to NEWNAME.
  import | csv  FILE  [-f|--force]
      Import lines with "NAME,SECRET,CODELENGTH" from CSV-file FILE.
      If -f/--force is given, existing entries NAME are overwritten.
  reveal | secret  NAME          Show Secret of entry NAME.
  clip | copy | cp  NAME         Put Code of entry NAME onto the clipboard.
  password | passwd | pw         Change database encryption password.
  version | --version | -V   Show version.
  help | --help | -h         Show this help text.
```
