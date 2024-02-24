package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"net/url"
	"regexp"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"golang.org/x/term"
)

const (
	version    = "0.8.12"
	maxNameLen = 20
	period     = 30
)

var (
	errr        = errors.New("Error")
	forceChange = false
	digits8     = false
	redirected  = true
	interrupt   = make(chan os.Signal)
)

func exitOnError(err error, errMsg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, red+"%s: "+yellow+"%s\n"+def, errMsg, err.Error())
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
	return uint32(bytes[0])<<24 + uint32(bytes[1])<<16 + uint32(bytes[2])<<8 + uint32(bytes[3])
}

func oneTimePassword(keyStr string) string {
	byteSecret, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(keyStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	value := toBytes(time.Now().Unix() / period)

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
		fmt.Fprintln(os.Stderr, red + "Invalid base32" + def + " (Valid characters: 2-7 and A-Z; ignored: spaces and dashes)")
		return ""
	}

	return secret
}

func addEntry(name, secret string) {
	if !forceChange && len([]rune(name)) > maxNameLen {
		exitOnError(errr, "Name longer than "+fmt.Sprint(maxNameLen))
	}

	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for adding entry")

	action := "added"
	if _, found := db.Entries[name]; found {
		if !forceChange {
			fmt.Fprintf(os.Stderr, yellow + "Entry '" + name + "' exists, confirm change [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadByte()
			if cfm != 'y' {
				fmt.Fprintln(os.Stderr, red + "Entry not changed")
				return
			}

		}
		action = "changed"
	}

	secret = checkBase32(secret)
	// If SECRET not supplied or invalid, ask for it
	reader := bufio.NewReader(os.Stdin)
	for secret == "" {
		fmt.Fprintf(os.Stderr, yellow + "Enter base32 Secret" + def + " [empty field to cancel]: ")
		secret, _ = reader.ReadString('\n')
		secret = strings.TrimSuffix(secret, "\n")
		if secret == "" {
			break
		}
		secret = checkBase32(secret)
	}
	if secret == "" {
		fmt.Fprintln(os.Stderr, cls + red + "Adding entry '" + name + "' cancelled")
		return
	}

	digits := 6
	if digits8 {
		digits = 8
	}
	db.Entries[name] = entry{
		Secret: strings.ToUpper(secret),
		Digits: digits,
	}
	err = saveDb(&db)
	exitOnError(err, cls+"Failure saving data file, entry not "+action)

	fmt.Fprintf(os.Stderr, cls+green+" Entry '"+yellow+name+green+" %s\n", action)
	if redirected {
		code := oneTimePassword(db.Entries[name].Secret)
		code = code[len(code)-db.Entries[name].Digits:]
		fmt.Println(code)
		return
	}

	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	for {
		code := oneTimePassword(db.Entries[name].Secret)
		code = code[len(code)-db.Entries[name].Digits:]
		left := period - time.Now().Unix()%period
		fmt.Fprintf(os.Stderr, blue+"\r Code: "+yellow+code+blue+"  Validity:"+yellow+
			" %2d"+blue+"s  "+def+"[Press "+green+"Ctrl-C"+def+" to exit] ", left)
		go func() {
			<-interrupt
			fmt.Fprintf(os.Stderr, cls)
			os.Exit(0)
		}()
		time.Sleep(time.Second)
	}
}

func showTotp(secret string) {
	secret = checkBase32(secret)
	// If SECRET not supplied or invalid, ask for it
	reader := bufio.NewReader(os.Stdin)
	for secret == "" {
		fmt.Fprintf(os.Stderr, yellow + "Enter base32 Secret" + def + " [empty field to cancel]: ")
		secret, _ = reader.ReadString('\n')
		secret = strings.TrimSuffix(secret, "\n")
		if secret == "" {
			break
		}
		secret = checkBase32(secret)
	}
	if secret == "" {
		return
	}

	digits := 6
	if digits8 {
		digits = 8
	}
	if redirected {
		code := oneTimePassword(strings.ToUpper(secret))
		code = code[len(code)-digits:]
		fmt.Println(code)
		return
	}

	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	for {
		code := oneTimePassword(strings.ToUpper(secret))
		code = code[len(code)-digits:]
		left := period - time.Now().Unix()%period
		fmt.Fprintf(os.Stderr, blue+"\r Code: "+yellow+code+blue+"  Validity:"+yellow+" %2d"+blue+"s  "+def+"[Press "+green+"Ctrl-C"+def+" to exit] ", left)
		go func() {
			<-interrupt
			fmt.Fprintf(os.Stderr, cls)
			os.Exit(0)
		}()
		time.Sleep(time.Second)
	}
}

func deleteEntry(name string) {
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for deleting entry")

	if _, found := db.Entries[name]; found {
		if !forceChange {
			fmt.Fprintf(os.Stderr, yellow + "Sure to delete entry '" + name + "'? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadByte()
			if cfm != 'y' {
				fmt.Fprintln(os.Stderr, red + "Entry not deleted")
				return
			}
		}

		delete(db.Entries, name)
		err = saveDb(&db)
		exitOnError(err, "Failure saving data file, entry not deleted")

		fmt.Fprintln(os.Stderr, green + "Entry '" + name + "' deleted")
	} else {
		fmt.Fprintln(os.Stderr, red + "Entry '" + name + "' not found")
	}
}

func changePassword() {
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for changing password")

	fmt.Fprintln(os.Stderr, green + "Changing password")
	err = initPassword(&db)
	exitOnError(err, "Failure changing password")

	err = saveDb(&db)
	exitOnError(err, "Failure saving data file, password not changed")

	fmt.Fprintln(os.Stderr, green + "Password change successful")
}

func revealSecret(name string) {
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for revealing Secret")

	secret := db.Entries[name].Secret
	if secret == "" {
		fmt.Fprintln(os.Stderr, red + "Entry '" + name + "' not found")
		return
	}

	if redirected {
		fmt.Printf("otpauth://totp/%s?secret=%s&digits=%d\n", url.PathEscape(name), secret, db.Entries[name].Digits)
		return
	}

	fmt.Fprintf(os.Stderr, "%s%s: %s%s%s\n", blue, name, yellow, secret, def)
	fmt.Fprintf(os.Stderr, "otpauth://totp/%s?secret=%s&digits=%d\n", url.PathEscape(name), secret, db.Entries[name].Digits)
	fmt.Fprintf(os.Stderr, def + "[Press "+green+"Ctrl-C"+def+" to exit] ")
	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	for {
		go func() {
			<-interrupt
			fmt.Fprintf(os.Stderr, cls)
			os.Exit(0)
		}()
		time.Sleep(time.Second)
	}
}

func renameEntry(name string, nname string) {
	if !forceChange && len([]rune(name)) > maxNameLen {
		exitOnError(errr, "NAME longer than "+fmt.Sprint(maxNameLen))
	}

	if !forceChange && len([]rune(nname)) > maxNameLen {
		exitOnError(errr, "NEWNAME longer than "+fmt.Sprint(maxNameLen))
	}

	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for renaming of entry")

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
	exitOnError(err, "Failure saving data file, entry not renamed")

	fmt.Fprintln(os.Stderr, green + "Entry '" + name + "' renamed to '" + nname + "'")
}

func clipCode(name string) {
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for copying Code to clipboard")

	if secret := db.Entries[name].Secret; secret == "" {
		fmt.Fprintln(os.Stderr, red + "Entry '" + name + "' not found")
		return
	}

	code := oneTimePassword(db.Entries[name].Secret)
	code = code[len(code)-db.Entries[name].Digits:]
	clipboard.WriteAll(code)
	left := period - time.Now().Unix()%period
	fmt.Fprintf(os.Stderr, green+"Code of "+yellow+"'"+name+"'"+green+" copied to clipboard, valid for"+yellow+" %d "+green+"s\n", left)
}

func showCodes(regex string) {
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for showing Codes")

	// Match regex and sort on name
	var names []string
	for name := range db.Entries {
		if match, _ := regexp.MatchString(regex, name); match {
			names = append(names, name)
		}
	}
	if redirected {
		for _, name := range names {
			code := oneTimePassword(db.Entries[name].Secret)
			tag := name
			if len(name) > maxNameLen {
				tag = name[:maxNameLen]
			}
			fmt.Printf("%v %v\n", code[len(code)-db.Entries[name].Digits:], tag)
		}
		return
	}

	nn := len(names)
	if nn == 0 {
		fmt.Fprintf(os.Stderr, red + "No entries")
		if regex != "" {
			fmt.Fprintln(os.Stderr, " matching Regex '" + regex + "'")
		}
		fmt.Fprintln(os.Stderr, def)
		return
	}

	// Check display capabilities
	w, h, _ := term.GetSize(int(os.Stdout.Fd()))
	cols := (w + 1) / (8 + 1 + maxNameLen + 1)
	if cols < 1 {
		exitOnError(errr, "Terminal too narrow to properly display entries")
	}

	if nn > cols*(h-1) {
		exitOnError(errr, "Terminal height too low, select fewer entries with REGEX")
	}

	sort.Strings(names)

	fmtstr := "%s %-" + fmt.Sprint(maxNameLen) + "s"
	for {
		fmt.Fprintf(os.Stderr, cls + blue + "   Code - Name")
		for i := 1; i < cols && i < nn; i++ {
			fmt.Fprintf(os.Stderr, strings.Repeat(" ", maxNameLen-1)+"Code - Name")
		}
		fmt.Fprintln(os.Stderr)
		n := 0
		for _, name := range names {
			code := oneTimePassword(db.Entries[name].Secret)
			code = fmt.Sprintf("%8v", code[len(code)-db.Entries[name].Digits:])
			tag := name
			if len(name) > maxNameLen {
				tag = name[:maxNameLen]
			}
			fmt.Fprintf(os.Stderr, fmtstr, green+code+def, tag)
			n += 1
			if n%cols == 0 {
				fmt.Fprintln(os.Stderr)
			} else {
				fmt.Fprintf(os.Stderr, " ")
			}
		}
		if n%cols > 0 {
			fmt.Fprintln(os.Stderr)
		}
		signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
		left := period - time.Now().Unix()%period
		for left > 0 {
			fmt.Fprintf(os.Stderr, blue+"\r Left:"+yellow+" %2d"+blue+"s  "+def+"[exit: "+green+"Ctrl-C"+def+"]", left)
			go func() {
				<-interrupt
				fmt.Fprintf(os.Stderr, cls)
				os.Exit(0)
			}()
			time.Sleep(time.Second)
			left--
		}
	}
}

func showNames(regex string) {
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for showing Names")

	// Match regex and sort on name
	var names []string
	for name := range db.Entries {
		if match, _ := regexp.MatchString(regex, name); match {
			names = append(names, name)
		}
	}
	if len(names) == 0 && !redirected {
		fmt.Fprintf(os.Stderr, red + "No entries")
		if regex != "" {
			fmt.Fprintf(os.Stderr, " matching Regex '" + regex + "'")
		}
		fmt.Fprintln(os.Stderr, def)
		return
	}

	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func exportEntries(filename string) {
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for showing Names")

	if filename == "" {
		for name := range db.Entries {
			line := fmt.Sprintf("otpauth://totp/%s?secret=%s&digits=%d",
				url.PathEscape(name), db.Entries[name].Secret, db.Entries[name].Digits)
			fmt.Println(line)
		}
		return
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		exitOnError(err, "Cannot create file or file exists")
	}

	for name := range db.Entries {
		line := fmt.Sprintf("otpauth://totp/%s?secret=%s&digits=%d\n",
			url.PathEscape(name), db.Entries[name].Secret, db.Entries[name].Digits)
		_, err = f.WriteString(line)
		if err != nil {
			exitOnError(err, "Error writing to "+filename)
		}
	}

	fmt.Fprintf(os.Stderr, "%sFile exported:%s %s\n",green, def, filename)
}

func importEntries(filename string) {
	file, err := os.Open(filename)
	exitOnError(err, "Could not open data file '"+filename+"'")

	reader := bufio.NewScanner(file)
	reader.Split(bufio.ScanLines)
	db, err := readDb(redirected)
	exitOnError(err, "Failure opening data file for import")

	// Check data, then admit to data file, but only save when no errors
	n, ns := 0, ""
	for reader.Scan() {
		digits, secret := 6, ""
		line := reader.Text()
		n++
		ns = fmt.Sprint(n)
		uri, err := url.Parse(line)
		exitOnError(err, "Invalid URI")

		if uri.Scheme != "otpauth" {
			exitOnError(errr, "URI scheme is not 'otpauth'")
		}

		if uri.Host != "totp" {
			exitOnError(errr, "The application is not 'totp'")
		}

		name := url.QueryEscape(uri.Path[1:])
		if len(name) == 0 {
			exitOnError(errr, "NAME must have content on line "+ns)
		}

		if len(name) > maxNameLen {
			if forceChange {
				fmt.Fprintf(os.Stderr, yellow+"WARNING"+def+": NAME longer than %d on line %d\n", maxNameLen, n)
			} else {
				exitOnError(errr, fmt.Sprintf("NAME longer than %d on line %d", maxNameLen, n))
			}
		}

		_, found := db.Entries[name]
		if found && !forceChange {
			exitOnError(errr, "Entry '"+name+"' on line "+ns+" exists, force overwrite with -f/--force")
		}

		query, err := url.ParseQuery(uri.RawQuery)
		exitOnError(err, "Invalid Query part of URI")

		for key, value := range query {
			switch key {
			case "secret":
				if len(value) > 1 {
					exitOnError(errr, "Multiple SECRETs on line "+ns)
				}

				secret = value[0]
				_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
				exitOnError(err, "Invalid base32 encoding in SECRET on line "+ns)

			case "digits":
				if len(value) > 1 {
					exitOnError(errr, "Multiple Code LENGTHs (key 'digits') on line "+ns)
				}

				digits, err = strconv.Atoi(value[0])
				exitOnError(err, "Code LENGTHs (key 'digits') not an integer")

				if digits != 6 && digits != 8 {
					exitOnError(errr, "Code LENGTH (key 'digits') on line "+ns+"not 6/8: "+value[0])
				}

			default:
				fmt.Fprintf(os.Stderr, yellow+"WARNING"+def+": key '"+key+"' on line "+ns+" unsupported\n")
			}
		}
		if len(secret) == 0 {
			exitOnError(errr, "SECRET must be given on line "+ns)
		}

		db.Entries[name] = entry{
			Secret: strings.ToUpper(secret),
			Digits: digits,
		}
	}
	file.Close()
	err = saveDb(&db)
	exitOnError(err, "Failure saving database, entries not imported")

	fmt.Fprintf(os.Stderr, green+"All %d entries in '"+filename+"' successfully imported\n", n)
}

func main() {
	self, cmd, regex, name, nname, secret, file, ddash := "", "", "", "", "", "", "", false
	o, _ := os.Stdout.Stat()
	if (o.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
		redirected = false
	}
	for _, arg := range os.Args {
		if self == "" { // Get binary name (arg0)
			selves := strings.Split(arg, "/")
			self = selves[len(selves)-1]
			continue
		}
		if cmd == "" { // Determine command
			switch arg { // First arg is command unless regex or dash-dash (arg1)
			case "show", "view":
				cmd = "s" // REGEX
			case "--":
				cmd, ddash = "s", true // REGEX
			case "list", "ls":
				cmd = "l" // REGEX
			case "help", "--help", "-h":
				usage("")
			case "version", "--version", "-V":
				fmt.Fprintln(os.Stderr, self + " version " + version)
				return

			case "rename", "move", "mv":
				cmd = "m" // NAME NEWNAME -f/--force
			case "add", "insert", "entry":
				cmd = "a" // NAME SECRET -8 -f/--force
			case "totp", "temp":
				cmd = "t" // SECRET -8
			case "reveal", "secret":
				cmd = "r" // NAME
			case "clip", "copy", "cp":
				cmd = "c" // NAME
			case "delete", "remove", "rm":
				cmd = "d" // NAME -f/--force
			case "password", "passwd", "pw":
				cmd = "p" // none
			case "export":
				cmd = "e" // FILE
			case "import":
				cmd = "i" // FILE -f/--force
			default: // No command, must be REGEX
				cmd, regex = "s", arg
			}
			continue
		}
		// Arguments arg0 (self) and arg1 (cmd/REGEX) have been parsed
		if !ddash && arg == "--" { // Catch '--' anywhere
			ddash = true
			continue
		}
		switch cmd { // Parse rest of args based on cmd
		case "p":
			usage("password command takes no argument")
		case "s":
			if regex != "" {
				usage("too many arguments, regular expression REGEX already given")
			}
			regex = arg
		case "l":
			if regex != "" {
				usage("too many arguments, regular expression REGEX already given")
			}
			regex = arg
		case "e":
			if file != "" {
				usage("too many arguments, file FILE already given")
			}
			file = arg
		case "i":
			if !ddash && (arg == "-f" || arg == "--force") {
				forceChange = true
				continue
			}
			if file != "" {
				usage("too many arguments, file FILE already given")
			}
			file = arg
		case "d":
			if !ddash && (arg == "-f" || arg == "--force") {
				forceChange = true
				continue
			}
			if name != "" {
				usage("too many arguments, NAME already given")
			}
			name = arg
		case "c", "r":
			if name != "" {
				usage("too many arguments, NAME already given")
			}
			name = arg
		case "m":
			if !ddash && (arg == "-f" || arg == "--force") {
				forceChange = true
				continue
			}
			if name != "" {
				if nname != "" {
					usage("too many arguments, NAME and NEWNAME already given")
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
			if !ddash && arg == "-8" {
				digits8 = true
				continue
			}
			if name != "" {
				if secret != "" {
					usage("too many arguments, NAME and SECRET already given")
				}
				secret = arg
			} else {
				name = arg
			}
		case "t":
			if !ddash && arg == "-8" {
				digits8 = true
				continue
			}
			if secret != "" {
				usage("too many arguments, SECRET already given")
			}
			secret = arg
		}
	}
	// All arguments have been parsed, check
	switch cmd {
	case "", "s":
		showCodes(regex)
	case "l":
		showNames(regex)
	case "a":
		if name == "" {
			usage("'add' command needs NAME as argument")
		}
		addEntry(name, secret)
	case "t":
		showTotp(secret)
	case "m":
		if name == "" || nname == "" {
			usage("'rename' command needs NAME and NEWNAME as arguments")
		}
		renameEntry(name, nname)
	case "r":
		if name == "" {
			usage("'reveal' command needs NAME as argument")
		}
		revealSecret(name)
	case "c":
		if name == "" {
			usage("'clip' command needs NAME as argument")
		}
		clipCode(name)
	case "d":
		if name == "" {
			usage("'delete' command needs NAME as argument")
		}
		deleteEntry(name)
	case "p":
		changePassword()
	case "e":
		exportEntries(file)
	case "i":
		if file == "" {
			usage("'import' command needs file FILE as argument")
		}
		importEntries(file)
	}
}

func usage(err string) {
	help := green + self + def + " v" + version + yellow + " - Manage TOTP data from CLI\n" +
		def + "The CLI is interactive & colorful, output to Stderr. SECRET can be piped in.\n" +
		"Only pertinent plain text information goes to Stdout when it is redirected.\n" +
		"* " + blue + "Repo" + def + ":       " + yellow + "github.com/pepa65/twofat" + def + " <pepa65@passchier.net>\n* " +
		blue + "Data file" + def + ":  " + yellow + dbPath + def + "  (depends on the file name of the binary)\n* " +
		blue + "Usage" + def + ":      " + yellow + self + def + " [" + green + "COMMAND" + def + "]\n" +
		green + "  COMMAND" + def + ":\n" +
		"[ " + green + "show" + def + " | " + green + "view" + def + " ]  [" + blue + "REGEX" + def + "]\n" +
		"    Display all Codes with Names [matching " + blue + "REGEX" + def + "] (the command is optional).\n" +
		green + "list" + def + " | " + green + "ls" + def + "  [" + blue + "REGEX" + def + "]\n" +
		"    List all Names [with Names matching " + blue + "REGEX" + def + "].\n" +
		green + "add" + def + " | " + green + "insert" + def + " | " + green + "entry  " + blue + "NAME" + def + "  [" + yellow + "-8" + def + "]  [" + yellow + "-f" + def + "|" + yellow + "--force" + def + "]  [" + blue + "SECRET" + def + "]\n" +
 		"   Add a new entry " + blue + "NAME" + def + " with " + blue + "SECRET" + def + " (queried when not given).\n" +
 		"   When " + yellow + "-8" + def + " is given, Code length is 8 digits, otherwise it is 6.\n" +
 		"   If " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": existing " + blue + "NAME" + def + " overwritten, no " + blue + "NAME" + def + " length check.\n" +
		green + "totp" + def + " | " + green + "temp" + def + "  [" + yellow + "-8" + def + "]  [" + blue + "SECRET" + def + "]\n" +
 		"   Show the Code for " + blue + "SECRET" + def + " (queried when not given).\n" +
 		"   When " + yellow + "-8" + def + " is given, Code length is 8 digits, otherwise it is 6.\n" +
 		"   (The data file is not queried nor written to.)\n" +
		green + "delete" + def + " | " + green + "remove" + def + " | " + green + "rm  " + blue + "NAME" + def + "  [" + yellow + "-f" + def + "|" + yellow + "--force" + def + "]\n" +
 		"   Delete entry " + blue + "NAME" + def + ". If " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": no confirmation asked.\n" +
		green + "rename" + def + " | " + green + "move" + def + " | " + green + "mv  " + blue + "NAME  NEWNAME" + def + "  [" + yellow + "-f" + def + "|" + yellow + "--force" + def + "]\n" +
 		"   Rename entry " + blue + "NAME" + def + " to " + blue + "NEWNAME" + def + ", if " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": no length checks.\n" +
		green + "import  " + blue + "FILE" + def + "  [" + yellow + "-f" + def + "|" + yellow + "--force" + def + "]\n" +
 		"   Import lines with OTPAUTH_URI from file " + blue + "FILE" + def + ".\n" +
 		"   If " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": existing " + blue + "NAME" + def + " overwritten, no " + blue + "NAME" + def + " length check.\n" +
		green + "export" + def + "  [" + blue + "FILE" + def + "]              Export OTPAUTH_URI-format entries [to file " + blue + "FILE" + def + "].\n" +
		green + "reveal" + def + " | " + green + "secret  " + blue + "NAME" + def + "       Show Secret of entry " + blue + "NAME" + def + ".\n" +
		green + "clip" + def + " | " + green + "copy" + def + " | " + green + "cp  " + blue + "NAME" + def + "      Put Code of entry " + blue + "NAME" + def + " onto the clipboard.\n" +
		green + "password" + def + " | " + green + "passwd" + def + " | " + green + "pw" + def + "      Change data file encryption password.\n" +
		green + "version" + def + " | " + green + "--version" + def + " | " + green + "-V" + def + "    Show version.\n" +
		green + "help" + def + " | " + green + "--help" + def + " | " + green + "-h" + def + "          Show this help text."
	fmt.Fprintln(os.Stderr, help)
	if err != "" {
		fmt.Fprintln(os.Stderr, red + "Abort: " + err)
		os.Exit(5)
	}
	os.Exit(0)
}
