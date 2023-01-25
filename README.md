# twofat
## Manage TOTP data from CLI
* **v0.7.1**
* Repo: [github.com/pepa65/twofat](https://github.com/pepa65/twofat)
* After: [github.com/slandx/tfat](https://github.com/slandx/tfat)
* Contact: github.com/pepa65
* Install: `wget -qO- gobinaries.com/pepa65/twofat |sh`

## Features
* Data saved with AES-GCM encrypt in ~/.twofat.enc, password changeable.
* Display codes of names matching regex, which auto-refresh.
* Add, rename, delete entry, reveal secret, copy code to clipboard.
* Import & export entries from & to standardized OTPAUTH_URI file.
* Displays well in 80-colums (or more) terminals. NAME display truncated to 20.

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
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o twofat
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags="-s -w" -o twofat_pi
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o twofat_bsd
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o twofat_osx
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o twofat.exe
```

## Usage
```
twofat v0.7.1 - Manage TOTP data from CLI
* Repo:       github.com/pepa65/twofat
* Data file:  ~/.twofat.enc  (depends on binary file name)
* Usage:      twofat [COMMAND]
  COMMAND:
[ show | view ]  [REGEX]
    Show all Codes [with Names matching REGEX] (the command is optional).
list | ls  [REGEX]
    Show all Names [with Names matching REGEX].
add | insert | entry  NAME  [-8]  [-f|--force]  [SECRET]
    Add a new entry NAME with SECRET (queried when not given).
    When -8 is given, Code LENGTH is 8 digits, otherwise it is 6.
    If -f/--force: existing NAME overwritten, no NAME length check.
totp | temp  [-8]  [SECRET]
    Show the Code for SECRET (queried when not given).
    When -8 is given, Code LENGTH is 8 digits, otherwise it is 6.
    (The data file is not queried nor written to.)
delete | remove | rm  NAME  [-f|--force]
    Delete entry NAME. If -f/--force: no confirmation asked.
rename | move | mv  NAME  NEWNAME  [-f|--force]
    Rename entry NAME to NEWNAME, if -f/--force: no length checks.
import  FILE  [-f|--force]
    Import lines with OTPAUTH_URI from file FILE.
    If -f/--force: existing NAME overwritten, no NAME length check.
export  FILE                Export all entries to OTPAUTH_URI file FILE.
reveal | secret  NAME       Show Secret of entry NAME.
clip | copy | cp  NAME      Put Code of entry NAME onto the clipboard.
password | passwd | pw      Change data file encryption password.
version | --version | -V    Show version.
help | --help | -h          Show this help text.
```

## Import/Export data
`twofat` abides by the backup standard from `https://authenticator.cc/docs/en/otp-backup-developer`.
Each line has a OTPAUTH_URI of the form: `otpauth://totp/NAME?secret=SECRET&digits=LENGTH`.
(The parameter `period` is fixed to `30` in almost all apps, and most all seem to use `SHA1` for the
`algorithm` parameter, `twofat` as well. As to `issuer`, this is not used/recorded in `twofat`.)
