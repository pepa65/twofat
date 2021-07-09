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
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
	"github.com/atotto/clipboard"
)

const (
	version    = "0.3.8"
	maxNameLen = 25
)

var (
	errr        = errors.New("Error")
	forceChange = false
	digits7     = false
	digits8     = false
	interrupt   = make(chan os.Signal)
)

func exitOnError(err error, errMsg string) {
	if err != nil {
		fmt.Printf(red+"%s: "+yellow+"%s\n"+def, errMsg, err.Error())
		os.Exit(1)
	}
}

func enter(ch chan bool) {
	terminal.ReadPassword(0)
	ch <-true
	fmt.Printf(cls)
	os.Exit(0)
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
	return (uint32(bytes[0]) << 24)+(uint32(bytes[1]) << 16)+
		(uint32(bytes[2]) << 8)+uint32(bytes[3])
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
	if secret == "" {
		return ""
	}
	_, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		fmt.Println(red+"Invalid base32"+def+" (Valid characters: 2-7 and A-Z; ignored: spaces and dashes)")
		return ""
	}
	return secret
}

func addEntry(name, secret string) {
	if len([]rune(name)) > maxNameLen {
		exitOnError(errr, "Name longer than "+fmt.Sprint(maxNameLen))
	}
	db, err := readDb()
	exitOnError(err, "Failure opening database for adding entry")
	action := "added"
	if _, found := db.Entries[name]; found {
		if !forceChange {
			fmt.Printf(yellow+"Entry '"+name+"' exists, confirm change [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadByte()
			if cfm != 'y' {
				fmt.Println(red+"Entry not changed")
				return
			}
		}
		action = "changed"
	}

	secret = checkBase32(secret)
	// If SECRET not supplied or invalid, ask for it
	reader := bufio.NewReader(os.Stdin)
	for secret == "" {
		fmt.Printf(yellow+"Enter base32 Secret"+def+" [empty field to cancel]: ")
		secret, _ = reader.ReadString('\n')
		secret = strings.TrimSuffix(secret, "\n")
		if secret == "" {
			break
		}
		secret = checkBase32(secret)
	}
	if secret == "" {
		fmt.Println(cls+red+"Adding entry '"+name+"' cancelled")
		return
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
	err = saveDb(&db)
	exitOnError(err, cls+"Failure saving database, entry not "+action)
	fmt.Printf(cls+green+"Entry '%s' %s\n", name, action)
}

func deleteEntry(name string) {
	db, err := readDb()
	exitOnError(err, "Failure opening database for deleting entry")
	if _, found := db.Entries[name]; found {
		if !forceChange {
			fmt.Printf(yellow+"Sure to delete entry '"+name+"'? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadByte()
			if cfm != 'y' {
				fmt.Println(red+"Entry not deleted")
				return
			}
		}
		delete(db.Entries, name)
		err = saveDb(&db)
		exitOnError(err, "Failure saving database, entry not deleted")
		fmt.Println(green+"Entry '"+name+"' deleted")
	} else {
		fmt.Println(red+"Entry '"+name+"' not found")
	}
}

func changePassword() {
	db, err := readDb()
	exitOnError(err, "Failure opening database for changing password")
	fmt.Println(green+"Changing password")
	err = initPassword(&db)
	exitOnError(err, "Failure changing password")
	err = saveDb(&db)
	exitOnError(err, "Failure saving database, password not changed")
	fmt.Println(green+"Password change successful")
}

func revealSecret(name string) {
	db, err := readDb()
	exitOnError(err, "Failure opening database for revealing Secret")
	secret := db.Entries[name].Secret
	if secret == "" {
		fmt.Println(red+"Entry '"+name+"' not found")
		return
	}
	fmt.Printf(blue+"%s: %s\notpauth://totp/default?secret=%s&period=30&digits=%d\n",	name, secret, secret, db.Entries[name].Digits)
	fmt.Printf(def+"[Press Enter to exit] ")
	ch := make(chan bool)
	go enter(ch)
	for {
		select {
			case <-ch:
			default: time.Sleep(time.Second)
		}
	}
}

func renameEntry(name string, nname string) {
	if len([]rune(name)) > maxNameLen {
		exitOnError(errr, "NAME longer than "+fmt.Sprint(maxNameLen))
	}
	if len([]rune(nname)) > maxNameLen {
		exitOnError(errr, "NEWNAME longer than "+fmt.Sprint(maxNameLen))
	}
	db, err := readDb()
	exitOnError(err, "Failure opening database for renaming of entry")

	if _, found := db.Entries[name]; found {
		if _, found := db.Entries[nname]; found {
			exitOnError(errr, "Entry '"+nname+"' already exists")
		}
	} else {
		exitOnError(errr, "Entry '"+name+"' not found")
	}
	// Name exists, Newname doesn't
	db.Entries[nname] = db.Entries[name]
	delete(db.Entries, name)
	err = saveDb(&db)
	exitOnError(err, "Failure saving database, entry not renamed")
	fmt.Println(green+"Entry '"+name+"' renamed to '"+nname+"'")
}

func clipCode(name string) {
	db, err := readDb()
	exitOnError(err, "Failure opening database for copying Code to clipboard")
	if secret := db.Entries[name].Secret; secret == "" {
		fmt.Println(red+"Entry '"+name+"' not found")
		return
	}
	code := oneTimePassword(db.Entries[name].Secret)
	code = code[len(code)-db.Entries[name].Digits:]
	clipboard.WriteAll(code)
	left := 30 - time.Now().Unix()%30
	fmt.Printf(green+"Code of "+yellow+"'"+name+"'"+green+" copied to clipboard, valid for"+yellow+" %d "+green+"s\n", left)
}

func showCodes(regex string) {
	db, err := readDb()
	exitOnError(err, "Failure opening database for showing Codes")

	// Match regex and sort on name
	var names []string
	for name := range db.Entries {
		if match, _ := regexp.MatchString(regex, name); match {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		fmt.Println(red+"No entries")
		if regex != "" {
			fmt.Println(" matching Regex '"+regex+"'")
		}
		return
	}
	sort.Strings(names)

	fmtstr := " %s  %-"+fmt.Sprint(maxNameLen)+"s"
	ch := make(chan bool,1)
	go enter(ch)
	for {
		fmt.Printf(cls+blue+"    Code    Name")
		if len(names) > 1 {
			fmt.Printf("                            Code    Name")
		}
		fmt.Println()
		first := true
		for _, name := range names {
			code := oneTimePassword(db.Entries[name].Secret)
			code = fmt.Sprintf("%8v", code[len(code)-db.Entries[name].Digits:])
			fmt.Printf(fmtstr, green+code+def, name)
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
		h, m, s := time.Now().Clock()
		left := 30-s%30
		s = s/30*30
		for left > 0 {
			select {
				case <-ch:
				default:
					fmt.Printf(blue+"\r %02d:%02d:%02d  Validity:"+yellow+" %2d"+
						blue+"s  "+def+"[Press Enter to exit] ", h, m, s, left)
					time.Sleep(time.Second)
					left--
			}
		}
	}
}

func importEntries(filename string) {
	csvfile, err := os.Open(filename)
	exitOnError(err, "Could not open database file '"+filename+"'")
	reader := csv.NewReader(bufio.NewReader(csvfile))
	db, err := readDb()
	exitOnError(err, "Failure opening database for import")

	// Check data, then admit to database, but only save when no errors
	n, ns := 0, ""
	var name, secret string
	var digits int
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		}
		n++
		ns = fmt.Sprint(n)
		exitOnError(err, "Error reading CSV data on line "+ns)
		if len(line) != 3 {
			exitOnError(errr, "Line "+ns+" doesn't have 3 fields")
		}
		name = line[0]
		secret = line[1]
		switch line[2] {
		case "6": digits = 6
		case "7": digits = 7
		case "8": digits = 8
		default:
			exitOnError(err, "Codelength (field 3) on line "+ns+"not 6/7/8: "+
				line[2])
		}
		if name == "" {
			exitOnError(errr, "Name (field 1) empty on line "+ns)
		}
		if secret == "" {
			exitOnError(errr, "Secret (field 2) empty on line "+ns)
		}
		if len(name) > maxNameLen {
			exitOnError(errr,
				fmt.Sprintf("Name (field 1) longer than %d on line %d", maxNameLen, n))
		}
		if _, found := db.Entries[name]; found && !forceChange {
			exitOnError(errr, "Entry '"+name+"' on line "+ns+" exists, force overwrite with -f/--force")
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).
			DecodeString(strings.ToUpper(secret)); err != nil {
			exitOnError(err, "Invalid base32 encoding in Secret (field 2) on line "+
				ns)
		}
		if digits < 6 || digits > 8 {
			exitOnError(errr, "Codelength (field 3) not 6, 7 or 8 on line "+ns)
		}
		db.Entries[name] = entry{
			Secret: strings.ToUpper(secret),
			Digits: digits,
		}
	}
	err = saveDb(&db)
	exitOnError(err, "Failure saving database, entries not imported")
	fmt.Printf(green+"All %d entries in '"+filename+"' successfully imported\n", n)
	return
}

func main() {
	self, cmd, regex, name, nname, secret, csvfile, ddash := "", "", "", "", "", "", "", false
	for _, arg := range os.Args {
		if self == "" { // Get binary name (arg0)
			selves := strings.Split(arg, "/")
			self = selves[len(selves)-1]
			continue
		}
		if cmd == "" { // Determine command
			switch arg { // First arg is command unless regex or dash-dash (arg1)
			case "show", "view", "list", "ls", "totp", "--":
				cmd = "s" // REGEX
			case "help", "h", "--help", "-h":
				usage("")
			case "version", "v", "--version", "-V":
				fmt.Println(self+" version "+version)
				return
			case "rename", "move", "mv":
				cmd = "m" // NAME NEWNAME
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
				cmd = "i" // FILE -f/--force
			default: // No command, must be REGEX
				cmd, regex = "s", arg
			}
			continue
		}
		if !ddash && arg == "--" {
			ddash = true
			continue
		}
		// Arguments arg0 (self) and arg1 (cmd/REGEX) have been parsed
		switch cmd { // Parse rest of args based on cmd
		case "p":
			usage("password command takes no ARGUMENT")
		case "s":
			if regex != "" {
				usage("too many ARGUMENTs, regular expression REGEX already given")
			}
			regex = arg
		case "i":
			if !ddash && (arg == "-f" || arg == "--force") {
				forceChange = true
				continue
			}
			if csvfile != "" {
				usage("too many ARGUMENTs, CSV-file FILE already given")
			}
			csvfile = arg
		case "d":
			if !ddash && (arg == "-f" || arg == "--force") {
				forceChange = true
				continue
			}
			if name != "" {
				usage("too many ARGUMENTs, NAME already given")
			}
			name = arg
		case "c", "r":
			if name != "" {
				usage("too many ARGUMENTs, NAME already given")
			}
			name = arg
		case "m":
			if name != "" {
				if nname != "" {
					usage("too many ARGUMENTs, NAME and NEWNAME already given")
				}
				nname = arg
			} else {
				name = arg
			}
		case "a":
			if !ddash && (arg == "-f" || arg == "--force") {
				forceChange = true
				continue
			}
			if !ddash && arg == "-7" {
				digits7 = true
				continue
			}
			if !ddash && arg == "-8" {
				digits8 = true
				continue
			}
			if name != "" {
				if secret != "" {
					usage("too many ARGUMENTs, NAME and SECRET already given")
				}
				secret = arg
			} else {
				name = arg
			}
		}
	}
	// All arguments have been parsed, check
	switch cmd {
	case "", "s":
		showCodes(regex)
	case "a":
		if digits7 && digits8 {
			usage("can't have both 7 and 8 length Code for the same entry")
		}
		if name == "" {
			usage("'add' command needs NAME as ARGUMENT")
		}
		addEntry(name, secret)
	case "m":
		if name == "" || nname == "" {
			usage("'rename' command needs NAME and NEWNAME as ARGUMENTs")
		}
		renameEntry(name, nname)
	case "r":
		if name == "" {
			usage("'reveal' command needs NAME as ARGUMENT")
		}
		revealSecret(name)
	case "c":
		if name == "" {
			usage("'clip' command needs NAME as ARGUMENT")
		}
		clipCode(name)
	case "d":
		if name == "" {
			usage("'delete' command needs NAME as ARGUMENT")
		}
		deleteEntry(name)
	case "p":
		changePassword()
	case "i":
		if csvfile == "" {
			usage("'import' command needs CSV-file FILE as ARGUMENT")
		}
		importEntries(csvfile)
	}
}

func usage(err string) {
	help := green+self+" v"+version+def+
		" - Manage a 2FA database from the commandline\n"+
		"* "+blue+"Repo"+def+
		":      "+yellow+"github.com/pepa65/twofat"+def+
		" <pepa65@passchier.net>\n* "+blue+"Database"+def+":  "+yellow+dbPath+
		def+"\n* "+blue+"Usage"+def+":     "+self+" ["+green+"COMMAND"+
		def+"] ["+green+"ARGUMENT"+def+"...]"+`
  [ show | view | list | ls | totp ]  [REGEX]
      Show all Codes (with Names matching REGEX).
  add | insert | entry  NAME  [-7|-8]  [-f|--force]  [SECRET]
      Add a new entry NAME with SECRET (queried when not given).
      When -7 or -8 are given, Code length is 7 or 8, otherwise it is 6.
      If -f/--force is given, no confirmation is asked when NAME exists.
  delete | remove | rm  NAME  [-f|--force]
      Delete entry NAME. If -f/--force is given, no confirmation is asked.
  rename | move | mv  NAME  NEWNAME       Rename entry from NAME to NEWNAME.
  import | csv  FILE  [-f|--force]
      Import lines with "NAME,SECRET,CODELENGTH" from CSV-file FILE.
      If -f/--force is given, existing entries NAME are overwritten.
  reveal | secret  NAME          Show Secret of entry NAME.
  clip | copy | cp  NAME         Put Code of entry NAME onto the clipboard.
  password | passwd | pw         Change database encryption password.
  version | v | --version | -V   Show version.
  help | h | --help | -h         Show this help text.`
	fmt.Println(help)
	if err != "" {
		fmt.Println(red+"Abort: "+err)
		os.Exit(5)
	}
	os.Exit(0)
}
