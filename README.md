# twofat
## Two Factor Authentication Tool
### Manage a 2FA database from the commandline
* **v0.3.0**
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
go build

# Or anywhere:
go get -u github.com/pepa65/twofat
```

## Usage
```
twofat version 0.3.0 - Two Factor Authentication Tool
* Purpose:   Manage a 2FA database from the commandline
* Repo:       github.com/pepa65/twofat <pepa65@passchier.net>
* Database:  /home/pp/.twofat.enc
* Usage:      twofat [COMMAND]
  COMMAND:
      [ show | view | list | ls | totp ]  [REGEX]
          Show all Codes (with Names matching REGEX).
      add | insert | entry  NAME  [-7|-8]  [-f|--force]  [SECRET]
          Add a new entry NAME with SECRET (queried when not given).
          When -7/-8 are not given, Code length is 6.
          If -f/--force is given, no confirmation is asked when NAME exists.
      delete | remove | rm  NAME  [-f|--force]
          Delete entry NAME. If -f/--force is given, no confirmation is asked.
      import | csv  CSVFILE  [-f|--force]
          Import lines with "NAME,SECRET,CODELENGTH" from CSVFILE.
          If -f/--force is given, existing entries with NAME are overwritten.
      reveal | secret  NAME          Show Secret of entry NAME.
      clip | copy | cp  NAME         Put Code of entry NAME onto the clipboard.
      password | passwd | pw         Change database encryption password.
      version | v | --version | -V   Show version.
      help | h | --help | -h         Show this help text.
```
