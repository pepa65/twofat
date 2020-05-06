package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
)

const (
	version    = "0.3.0"
	maxNameLen = 25
)

var (
	errr        = errors.New("Error")
	forceChange = false
	digits7     = false
	digits8     = false
	interrupt   = make(chan os.Signal)
)

func cls() {
	fmt.Print("\033c")
}

func exitOnError(err error, errMsg string) {
	if err != nil {
		fmt.Printf("%s: %s\n", errMsg, err.Error())
		os.Exit(1)
	}
}

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) + (uint32(bytes[2]) << 8) +
		uint32(bytes[3])
}

func oneTimePassword(keyStr string) string {
	byteSecret, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(keyStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	value := toBytes(time.Now().Unix() / 30)

	// Sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, byteSecret)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)
	offset := hash[len(hash)-1] & 0x0F

	// Get 32-bit chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// Ignore most significant bit 0x80 (RFC4226)
	hashParts[0] = hashParts[0] & 0x7F
	number := toUint32(hashParts)
	return fmt.Sprintf("%08d", number)
}

func checkBase32(secret string) string {
	secret = strings.ToUpper(secret)
	secret = strings.ReplaceAll(secret, "-", "")
	secret = strings.ReplaceAll(secret, " ", "")
	if len(secret) == 0 {
		return ""
	}
	_, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		fmt.Println("Invalid base32 (Only characters 2-7 and A-Z; spaces and dashes are ignored.)")
		return ""
	}
	return secret
}

func addEntry(name, secret string) {
	if len(name) == 0 {
		exitOnError(errr, "zero length Name")
	}
	if len([]rune(name)) > maxNameLen {
		exitOnError(errr, fmt.Sprintf("Name longer than %d", maxNameLen))
	}
	db, err := readDb()
	exitOnError(err, "Open database to manage entry failed")
	action := "Added"
	if _, found := db.Entries[name]; found {
		if !forceChange {
			fmt.Printf("entry with Name '" + name + "' already exists, sure to change? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadString('\n')
			if cfm[0] != 'y' {
				fmt.Println("entry not changed")
				return
			}
		}
	}

	secret = checkBase32(secret)
	// If SECRET not supplied or invalid, ask for it
	reader := bufio.NewReader(os.Stdin)
	for len(secret) == 0 || err != nil {
		fmt.Println("Enter base32 Secret [empty field to cancel]: ")
		secret, _ = reader.ReadString('\n')
		secret = strings.TrimSuffix(secret, "\n")
		secret = checkBase32(secret)
		if len(secret) == 0 {
			fmt.Println("Operation cancelled")
			return
		}
	}

	digits := 6
	if digits7 {
		digits = 7
	}
	if digits8 {
		digits = 8
	}
	db.Entries[name] = entry{
		Secret: strings.ToUpper(secret),
		Digits: digits,
	}
	cls()
	saveDb(&db)
	fmt.Printf("%s %s\n", action, name)
	return
}

func deleteEntry(name string) {
	db, err := readDb()
	exitOnError(err, "Open database to delete entry failed")
	if _, found := db.Entries[name]; found {
		if !forceChange {
			fmt.Printf("Sure to delete entry with Name '" + name + "'? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadString('\n')
			if cfm[0] != 'y' {
				fmt.Println("entry not deleted")
				return
			}
		}
		delete(db.Entries, name)
		err = saveDb(&db)
		exitOnError(err, "Failed to delete entry")
		fmt.Println("Entry with Name '" + name + "' deleted")
	} else {
		fmt.Printf("Entry with Name '%s' not found\n", name)
	}
}

func changePassword() {
	db, err := readDb()
	exitOnError(err, "wrong password")
	fmt.Println("Changing password")
	err = initPassword(&db)
	exitOnError(err, "failed to change password")
	saveDb(&db)
	fmt.Println("Password change successful")
}

func revealSecret(name string) {
	db, err := readDb()
	exitOnError(err, "Open database to reveal Secret failed")
	secret := db.Entries[name].Secret
	if len(secret) == 0 {
		fmt.Printf("Entry with Name '%s' not found\n", name)
		return
	}
	fmt.Printf("%s: %s\notpauth://totp/default?secret=%s&period=30&digits=%d\n",
		name, secret, secret, db.Entries[name].Digits)
	fmt.Printf("[Ctrl+C to exit] ")
	// Handle Ctrl-C
	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	go func() {
		<-interrupt
		cls()
		os.Exit(3)
	}()
	for true {
		time.Sleep(time.Hour)
	}
}

func clipCode(name string) {
	db, err := readDb()
	exitOnError(err, "Open database to copy Code to clipboard failed")
	if secret := db.Entries[name].Secret; len(secret) == 0 {
		fmt.Printf("Entry with Name '%s' not found\n", name)
		return
	}
	code := oneTimePassword(db.Entries[name].Secret)
	code = code[len(code)-db.Entries[name].Digits:]
	clipboard.WriteAll(code)
	left := 30 - time.Now().Unix()%30
	fmt.Printf("%s Code copied, valididity: %ds\n", name, left)
}

func showCodes(regex string) {
	db, err := readDb()
	exitOnError(err, "Failed to read database")

	// Match regex and sort on name
	var names []string
	for name := range db.Entries {
		if match, _ := regexp.MatchString(regex, name); match {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		fmt.Printf("No entries")
		if regex != "" {
			fmt.Printf(" matching Regex '%s'", regex)
		}
		fmt.Println()
		return
	}
	sort.Strings(names)

	// Handle Ctrl-C
	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	go func() {
		<-interrupt
		cls()
		os.Exit(4)
	}()
	fmtstr := " %8s  %-" + strconv.Itoa(maxNameLen) + "s"
	for true {
		cls()
		first := true
		for _, name := range names {
			code := oneTimePassword(db.Entries[name].Secret)
			code = code[len(code)-db.Entries[name].Digits:]
			fmt.Printf(fmtstr, code, name)
			if first {
				first = false
				fmt.Printf("    ")
			} else {
				first = true
				fmt.Println()
			}
		}
		if !first {
			fmt.Println()
		}
		left := 30 - time.Now().Unix()%30
		for left > 0 {
			fmt.Printf("\rValidity: %2ds    [Ctrl+C to exit] ", left)
			time.Sleep(time.Second)
			left--
		}
	}
	cls()
}

func importEntries(filename string) {
	csvfile, err := os.Open(filename)
	exitOnError(err, "Could not open fatabase with filename '"+filename+"'")
	reader := csv.NewReader(bufio.NewReader(csvfile))
	db, err := readDb()
	exitOnError(err, "Open database to import entries failed")

	// Check data, then admit to database, but only save when no errors
	n := 0
	var name, secret string
	var digits int
	for {
		n++
		ns := strconv.Itoa(n)
		line, err := reader.Read()
		if err == io.EOF {
			break
		}
		exitOnError(err, "error reading CSV data on line "+ns)
		if len(line) != 3 {
			exitOnError(errr, "line "+ns+" doesn't have 3 fields")
		}
		name = line[0]
		secret = line[1]
		digits, err = strconv.Atoi(line[2])
		exitOnError(err, "not an integer in Codelength (field 3) on line "+ns+": "+line[2])
		if len(name) == 0 || len(secret) == 0 {
			exitOnError(errr, "Name (field 1) empty on line "+ns)
		}
		if len(name) > maxNameLen {
			exitOnError(errr,
				fmt.Sprintf("Name (field 1) longer than %d on line %d", maxNameLen, n))
		}
		if _, found := db.Entries[name]; found && !forceChange {
			exitOnError(errr, "entry with Name '"+name+"' on line "+ns+
				" already exists, force with -f/--force")
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).
			DecodeString(strings.ToUpper(secret)); err != nil {
			exitOnError(err, "invalid base32 encoding in Secret (field 2) on line "+ns)
		}
		if digits < 6 || digits > 8 {
			exitOnError(errr, "Codelength (field 3) not 6, 7 or 8 on line "+ns)
		}
		db.Entries[name] = entry{
			Secret: strings.ToUpper(secret),
			Digits: digits,
		}
	}
	saveDb(&db)
	fmt.Printf("All %d entries in '%s' successfully imported\n", n, filename)
	return
}

func main() {
	self, cmd, regex, name, secret, csvfile := "", "", "", "", "", ""
	for _, arg := range os.Args {
		if self == "" { // Get binary name (arg0)
			selves := strings.Split(arg, "/")
			self = selves[len(selves)-1]
			continue
		}
		if cmd == "" { // Get command
			switch arg { // First argument is command unless only regex (arg1)
			case "help", "h", "--help", "-h":
				usage("")
			case "version", "v", "--version", "-V":
				fmt.Println(self + " version " + version)
				return
			case "add", "insert", "entry":
				cmd = "a" // NAME SECRET -7 -8 -f/--force
			case "reveal", "secret":
				cmd = "r" // NAME
			case "clip", "copy", "cp":
				cmd = "c" // NAME
			case "delete", "remove", "rm":
				cmd = "d" // NAME -f/--force
			case "password", "passwd", "pw":
				cmd = "p" // none
			case "import", "csv":
				cmd = "i" // CSVFILE -f/--force
			case "show", "view", "list", "ls", "totp":
				cmd = "s" // REGEX
			default: // No command, must be REGEX
				cmd, regex = "s", arg
			}
			continue
		}
		// Arguments arg0 (self) and arg1 (cmd/REGEX) are parsed
		switch cmd { // Parse arg based on cmd
		case "p":
			usage("password command takes no argument: " + arg)
		case "s":
			if regex != "" {
				usage("more than 1 regular expression: " + arg)
			}
			regex = arg
		case "i":
			if arg == "-f" || arg == "--force" {
				forceChange = true
				continue
			}
			if csvfile != "" {
				usage("more than 1 CSV filename: " + arg)
			}
			csvfile = arg
		case "d":
			if arg == "-f" || arg == "--force" {
				forceChange = true
				continue
			}
			if name != "" {
				usage("more than 1 entry name: " + arg)
			}
			name = arg
		case "c", "r":
			if name != "" {
				usage("more than 1 entry name: " + arg)
			}
			name = arg
		case "a":
			if arg == "-f" || arg == "--force" {
				forceChange = true
				continue
			}
			if arg == "-7" {
				digits7 = true
				continue
			}
			if arg == "-8" {
				digits8 = true
				continue
			}
			if name != "" {
				if secret != "" {
					usage("too many arguments, Name and Secret already given: " + arg)
				}
				secret = arg
			} else {
				name = arg
			}
		}
	}
	// All arguments have been parsed
	if digits7 && digits8 {
		usage("can't have both 7 and 8 length Code for the same entry")
	}
	switch cmd {
	case "", "s": showCodes(regex)
	case "a": addEntry(name, secret)
	case "r": revealSecret(name)
	case "c": clipCode(name)
	case "d": deleteEntry(name)
	case "p": changePassword()
	case "i": importEntries(csvfile)
	}
}

func usage(err string) {
	help := self + " version " + version + " - Two Factor Authentication Tool" +
		"\n* Purpose:   Manage a 2FA database from the commandline" +
		"\n* Repo:      github.com/pepa65/twofat <pepa65@passchier.net>" +
		"\n* Database:  " + dbPath + `
* Usage:     twofat [COMMAND]
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
      help | h | --help | -h         Show this help text.`

  fmt.Println(help)
  if err != "" {
    fmt.Println("Abort: " + err)
    os.Exit(1)
  } else {
    os.Exit(0)
  }
}
