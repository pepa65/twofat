# twofat
<img src="https://raw.githubusercontent.com/pepa65/twofat/master/twofat.png" width="96" alt="twofat icon" align="right">

## Manage TOTPs from CLI
* **v2.0.7**
* Repo: [github.com/pepa65/twofat](https://github.com/pepa65/twofat)
* After: [github.com/slandx/tfat](https://github.com/slandx/tfat)
* Contact: github.com/pepa65
* Install: `wget -qO- gobinaries.com/pepa65/twofat |sh`
* Migration from pre v1.0.0 versions of twofat:
  **Export the data with twofat v0 and import that with twofat v1.**
* Migration from pre v2.0.0 versions of twofat:
  **Export the data with twofat v1 (or v0) and import that with twofat v2.**

### Features
* Data saved with AES-GCM encrypt in ~/.twofat.enc (by default).
* Memory is wiped of SECRETs, garbage collected. Best not to give SECRET on the commandline!
  For even more security, run like: `GODEBUG=clobberfree=1 twofat`
* Datafile password can be changed.
* Display TOTPs of names matching regex, which auto-refresh.
* Add, rename, delete entry, reveal secret, copy TOTP to clipboard.
* Import & export entries from & to standardized OTPAUTH_URI file.
* Adjusts to terminal width for display. NAME truncated to 20 on display
  (shown in full on `export` and `ls`/`list`).
* Implementing RFC 4226/6238:
  - Defaults to HMAC-SHA-1 hashing, but allows HMAC-SHA-256 and HMAC-SHA-512.
  - Defaults to a TOTP length of 6, but allows 5 (for Steam), 7 (Twitch) and 8 (no other lengths seem to be in use).
  - The minimum SECRET length (128 bit, or 26 base32-chars) is not enforced (1 char is the minimum).
    Most OTP servers seem to use less than the minimum (security is not significantly reduced).
    There is no maximum length for a SECRET in twofat.
  - A 30 second timeout seems to be more or less universal, and twofat only supports 30 for period LENGTH.
    (Making this shorter does little to prevent the success of brute-force attacks.)

## Build
```shell
# While in the repo root directory:
go build

# Or anywhere:
go get -u github.com/pepa65/twofat

# Smaller binary:
go build -ldflags="-s -w"

# More extreme shrinking:
upx twofat*

# Build for various architectures:
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o twofat
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags="-s -w" -o twofat_pi
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o twofat_bsd
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o twofat_osx
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o twofat.exe
```

## Usage
```
twofat v2.0.7 - Manage TOTPs from CLI
The CLI is interactive & colorful, output to Stderr. Password can be piped in.
When output is redirected, only pertinent plain text is sent to Stdout.
* Repo:       github.com/pepa65/twofat <pepa65@passchier.net>
* Data file:  ~/.twofat.enc  (default, depends on the binary's name)
* Usage:      twofat  [COMMAND]  [ -d | --datafile  DATAFILE ]
  == COMMAND:
[ show | view ]  [REGEX]
    Display all TOTPs with NAMEs [matching REGEX] (show/view is optional).
list | ls  [REGEX]
    List all NAMEs [matching REGEX].
add | insert | entry  NAME  [TOTP-OPTIONS]  [ -f | --force ]  [SECRET]
    Add a new entry NAME with SECRET (queried when not given).
    If -f/--force: existing NAME overwritten, no NAME max.length check.
totp | temp  [TOTP-OPTIONS]  [SECRET]
    Show the TOTP for SECRET (queried when not given), no datafile access.
delete | remove | rm  NAME  [ -f | --force ]
    Delete entry NAME. If -f/--force: no confirmation asked.
rename | move | mv  NAME  NEWNAME  [ -f | --force ]
    Rename entry NAME to NEWNAME, if -f/--force: no max.length checks.
import  FILE  [ -f | --force ]
    Import lines with OTPAUTH_URI from file FILE.
    If -f/--force: existing NAME overwritten, no NAME max.length check.
export  [FILE]              Export OTPAUTH_URI-format entries [to file FILE].
reveal | secret  NAME       Show Secret of entry NAME.
clip | copy | cp  NAME      Put TOTP of entry NAME onto the clipboard.
password | passwd | pw      Change datafile encryption password.
version | --version | -V    Show version.
help | --help | -h          Show this help text.
  == TOTP-OPTIONS:
-s | --size  LENGTH       TOTP length: 5-8 (default: 6)
-a | --algorithm  HASH    Hash algorithm: SHA1/SHA256/SHA512 (default: SHA1)
```

### Import/Export data
`twofat` abides by the backup standard from:
https://www.ietf.org/archive/id/draft-linuxgemini-otpauth-uri-01.html

Each exported line has a otpauth URI of the form:
`otpauth://totp/NAME?secret=SECRET&algorithm=HASH&digits=LENGTH&period=PERIOD&issuer=NAME`
(the capitalized parts are variable parameters: `NAME`, `SECRET`, `HASH`, `LENGTH`, `PERIOD`).

* The `NAME` should not have a colon `:` or `%` (messes with URI conversion).
  (`NAME` could be `ISSUER:ACCOUNTNAME`, but `twofat` uses the full `NAME` for the `issuer` parameter.)
* The `SECRET` is the base32 RFC3548 seed (without the `=` padding!) for the OTPs.
* `NAME` and `SECRET` are mandatory.
* The `HASH` for `algorithm` is `SHA1` (the default), `SHA256` or `SHA512`.
* The `LENGTH` for `digits` is most often `6`, but can be set to `5` (for Steam), `7` (Twitch) or `8` (Microsoft).
* The `PERIOD` for `period` is fixed to `30` (the default) in (almost?) all apps.
* On import, `digits`, `period` and `algorithm` will be set to the defaults when not specified.
* The `issuer` is set to `NAME` on export from `twofat`, and is ignored on import.

