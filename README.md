# twofat
## Manage a 2FA database from the commandline
* **v0.3.2**
* Repo: [github.com/pepa65/twofat](https://github.com/pepa65/twofat)
* After: [github.com/slandx/tfat](https://github.com/slandx/tfat)
+ Contact: pepa65 <pepa65@passchier.net>

## Features
* Data saved with AES-GCM encrypt in ~/.<binaryname>.enc, password changable.
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

# Other architectures:
GOOS=linux GOARCH=arm go build -ldflags="-s -w" -o twofat_arm
GOOS=freebsd GOARCH=amd54 go build -ldflags="-s -w" -o twofat_freebsd
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o twofat_osx
```

## Usage
```
twofat version 0.3.2 - Manage a 2FA database from the commandline
* Repo:       github.com/pepa65/twofat <pepa65@passchier.net>
* Database:  /home/pp/.twofat.enc
* Usage:      twofat [COMMAND]
    [ show | view | list | ls | totp ]  [REGEX]
        Show all Codes (with Names matching REGEX).
    add | insert | entry  NAME  [-7|-8]  [-f|--force]  [SECRET]
        Add a new entry NAME with SECRET (queried when not given).
        When -7 or -8 are given, Code length is 7 or 8, otherwise it is 6.
        If -f/--force is given, no confirmation is asked when NAME exists.
    delete | remove | rm  NAME  [-f|--force]
        Delete entry NAME. If -f/--force is given, no confirmation is asked.
    rename | move | mv  NAME  NEWNAME
        Rename entry's Name from NAME to NEWNAME.
    import | csv  CSVFILE  [-f|--force]
        Import lines with "NAME,SECRET,CODELENGTH" from CSVFILE.
        If -f/--force is given, existing entries with NAME are overwritten.
    reveal | secret  NAME          Show Secret of entry NAME.
    clip | copy | cp  NAME         Put Code of entry NAME onto the clipboard.
    password | passwd | pw         Change database encryption password.
    version | v | --version | -V   Show version.
    help | h | --help | -h         Show this help text.
```
