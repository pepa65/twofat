package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"golang.org/x/term"
)

const (
	version    = "2.2.8"
	maxNameLen = 20
	period     = 30
)

var (
	errr       = errors.New("Error")
	force      = false
	redirected = true
	interrupt  = make(chan os.Signal)
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

func wipe(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
	runtime.GC()
}

func oneTimePassword(secret []byte, size, algorithm string, epoch int64) string {
	decsecret := make([]byte, base32.StdEncoding.WithPadding(base32.NoPadding).DecodedLen(len(secret)))
	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).Decode(decsecret, secret)
	//wipe(secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}

	value := toBytes((time.Now().Unix() + 30*epoch) / period)
	var hash []byte
	switch algorithm {
		case "SHA1": // Sign the value using HMAC-SHA1
			hmacSha1 := hmac.New(sha1.New, decsecret)
			wipe(decsecret)
			hmacSha1.Write(value)
			hash = hmacSha1.Sum(nil)
		case "SHA256": // Sign the value using HMAC-SHA256
			hmacSha256 := hmac.New(sha256.New, decsecret)
			wipe(decsecret)
			hmacSha256.Write(value)
			hash = hmacSha256.Sum(nil)
		case "SHA512": // Sign the value using HMAC-SHA512
			hmacSha512 := hmac.New(sha512.New, decsecret)
			wipe(decsecret)
			hmacSha512.Write(value)
			hash = hmacSha512.Sum(nil)
		default:
			wipe(decsecret)
			exitOnError(errr, "Unsupported algorithm: "+algorithm)
	}

	offset := hash[len(hash)-1] & 0x0F
	// Get 32-bit chunk from the hash starting at offset
	hmacParts := hash[offset:offset+4]
	// Ignore most significant bit 0x80 (RFC4226)
	hmacParts[0] = hmacParts[0] & 0x7F
	totp := fmt.Sprintf("%08d", toUint32(hmacParts) % 100000000)
	l := int(size[0]) - 48
	return totp[8-l:]
}

func checkBase32(secret []byte) []byte {
	secret = bytes.ToUpper(secret)
	secret = slices.DeleteFunc(secret, func(b byte) bool {
		return b == '-' || b == ' ' || b == '=' || b == '\n'
	})
	if len(secret) == 0 {
		return nil
	}

	decsecret := make([]byte, base32.StdEncoding.WithPadding(base32.NoPadding).DecodedLen(len(secret)))
	_, e := base32.StdEncoding.WithPadding(base32.NoPadding).Decode(decsecret, secret)
	wipe(decsecret)
	if e != nil {
		fmt.Fprintln(os.Stderr, red+"Invalid base32"+def+" (Valid characters: 2-7 and A-Z; ignored: spaces and dashes)")
		return nil
	}

	return secret
}

func addEntry(name string, secret []byte, size, algorithm string, clearscr bool) {
	clr := ""
	if clearscr {
		clr = cls
	}
	if !force && len([]rune(name)) > maxNameLen {
		exitOnError(errr, clr+"Name longer than "+fmt.Sprint(maxNameLen))
	}

	// NAME should not have a colon or percent sign
	if strings.Contains(name, ":") || strings.Contains(name, "%") {
		exitOnError(errr, clr+"Entry '"+name+"' contains ':' or '%'")
	}

	db, err := readDb(clearscr)
	exitOnError(err, "Failure opening datafile for adding entry")

	action := "added"
	if _, found := db.Entries[name]; found {
		if !force {
			fmt.Fprintf(os.Stderr, yellow+"Entry '"+name+"' exists, confirm change [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadByte()
			if cfm != 'y' && cfm != 'Y' {
				fmt.Fprintln(os.Stderr, red+"Entry not changed")
				return
			}

		}
		action = "changed"
	}

	// If SECRET not given or invalid, ask for it
	reader := bufio.NewReader(os.Stdin)
	for len(secret) == 0 {
		fmt.Fprintf(os.Stderr, yellow+"Enter base32 Secret"+def+" [empty field to cancel]: ")
		secret, _ = reader.ReadBytes('\n')
		if len(secret) == 0 {
			return
		}
		secret = checkBase32(secret)
	}
	if len(secret) == 0 {
		fmt.Fprintln(os.Stderr, red+"Adding entry '"+name+"' cancelled")
		return
	}

	fmt.Fprintf(os.Stderr, cls)
	db.Entries[name] = entry{
		Secret:    secret,
		Digits:    size,
		Algorithm: algorithm,
	}
	err = saveDb(&db)
	exitOnError(err, "Failure saving datafile, entry not "+action)

	fmt.Fprintf(os.Stderr, green+" Entry '"+yellow+name+green+"' %s\n", action)
	if redirected {
		totp := oneTimePassword(secret, size, algorithm, 0)
		fmt.Println(totp)
		wipe(secret)
		return
	}

	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	for {
		totp := oneTimePassword(secret, size, algorithm, 0)
		ntotp := oneTimePassword(secret, size, algorithm, 1)
		left := period - time.Now().Unix()%period
		fmt.Fprintf(os.Stderr, blue+"\r TOTP: "+green+totp+blue+"  Next: "+magenta+ntotp+blue+"  Validity:"+yellow+
			" %2d"+blue+"s  "+def+"[Press "+green+"Ctrl-C"+def+" to exit] ", left)
		go func() {
			<-interrupt
			fmt.Fprintf(os.Stderr, cls)
			wipe(secret)
			os.Exit(0)
		}()
		time.Sleep(time.Second)
	}
}

func showSingleTotp(secret []byte, size, algorithm string) {
	// If SECRET not given or invalid, ask for it
	reader := bufio.NewReader(os.Stdin)
	for len(secret) == 0 {
		fmt.Fprintf(os.Stderr, yellow+"Enter base32 Secret"+def+" [empty field to cancel]: ")
		secret, _ = reader.ReadBytes('\n')
		if len(secret) == 0 { // Nothing entered, bail
			return
		}

		secret = checkBase32(secret)
	}
	if redirected {
		totp := oneTimePassword(secret, size, algorithm, 0)
		wipe(secret)
		fmt.Println(totp)
		return
	}

	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	for {
		totp := oneTimePassword(secret, size, algorithm, 0)
		ntotp := oneTimePassword(secret, size, algorithm, 1)
		left := period - time.Now().Unix()%period
		fmt.Fprintf(os.Stderr, blue+"\r TOTP: "+green+totp+blue+"  Next: "+magenta+ntotp+blue+"  Validity:"+yellow+" %2d"+blue+"s  "+def+"[Press "+green+"Ctrl-C"+def+" to exit] ", left)
		go func() {
			<-interrupt
			fmt.Fprintf(os.Stderr, cls)
			wipe(secret)
			os.Exit(0)
		}()
		time.Sleep(time.Second)
	}
}

func deleteEntry(name string) {
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for deleting entry")

	if _, found := db.Entries[name]; found {
		if !force {
			fmt.Fprintf(os.Stderr, yellow+"Sure to delete entry '"+name+"'? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadByte()
			if cfm != 'y' {
				fmt.Fprintln(os.Stderr, red+"Entry not deleted")
				return
			}
		}

		delete(db.Entries, name)
		err = saveDb(&db)
		exitOnError(err, "Failure saving datafile, entry not deleted")

		fmt.Fprintln(os.Stderr, green+"Entry '"+name+"' deleted")
	} else {
		fmt.Fprintln(os.Stderr, red+"Entry '"+name+"' not found")
	}
}

func changePassword() {
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for changing password")

	fmt.Fprintln(os.Stderr, green+"Changing password")
	err = initPassword(&db)
	exitOnError(err, "Failure changing password")

	err = saveDb(&db)
	exitOnError(err, "Failure saving datafile, password not changed")

	fmt.Fprintln(os.Stderr, green+"Password change successful")
}

func revealSecret(name string) {
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for revealing Secret")

	secret := db.Entries[name].Secret
	if len(secret) == 0 {
		fmt.Fprintln(os.Stderr, red+"Entry '"+name+"' not found")
		return
	}

	if redirected {
		fmt.Printf("otpauth://totp/%s?secret=%s&algorithm=%s&digits=%s&period=30&issuer=%s\n", url.PathEscape(name), string(secret), db.Entries[name].Algorithm, db.Entries[name].Digits, url.PathEscape(name))
		wipe(secret)
		return
	}

	fmt.Fprintf(os.Stderr, "%s%s: %s%s%s\n", blue, name, yellow, string(secret), def)
	fmt.Fprintf(os.Stderr, "otpauth://totp/%s?secret=%s&algorithm=%s&digits=%s&period=30&issuer=%s\n", url.PathEscape(name), string(secret), db.Entries[name].Algorithm, db.Entries[name].Digits, url.PathEscape(name))
	fmt.Fprintf(os.Stderr, def+"[Press "+green+"Ctrl-C"+def+" to exit] ")
	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	for {
		go func() {
			<-interrupt
			fmt.Fprintf(os.Stderr, cls)
			wipe(secret)
			os.Exit(0)
		}()
		time.Sleep(time.Second)
	}
}

func renameEntry(name string, nname string) {
	if !force && len([]rune(name)) > maxNameLen {
		exitOnError(errr, "NAME longer than "+fmt.Sprint(maxNameLen))
	}

	if !force && len([]rune(nname)) > maxNameLen {
		exitOnError(errr, "NEWNAME longer than "+fmt.Sprint(maxNameLen))
	}

	// NEWNAME should not have a colon or percent sign
	if strings.Contains(nname, ":") || strings.Contains(nname, "%") {
		fmt.Fprintln(os.Stderr, red+"Entry '"+nname+"' contains ':' or '%'")
		return
	}

	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for renaming of entry")

	if _, found := db.Entries[name]; found {
		if _, found := db.Entries[nname]; found {
			exitOnError(errr, "Entry '"+nname+"' already exists")
		}
	} else {
		exitOnError(errr, "Entry '"+name+"' not found")
	}

	// NAME exists, NEWNAME doesn't
	db.Entries[nname] = db.Entries[name]
	delete(db.Entries, name)
	err = saveDb(&db)
	exitOnError(err, "Failure saving datafile, entry not renamed")

	fmt.Fprintln(os.Stderr, green+"Entry '"+name+"' renamed to '"+nname+"'")
}

func clipTOTP(name string) {
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for copying TOTP to clipboard")

	secret := db.Entries[name].Secret
	if len(secret) == 0 {
		fmt.Fprintln(os.Stderr, red+"Entry '"+name+"' not found")
		return
	}

	totp := oneTimePassword(secret, db.Entries[name].Digits, db.Entries[name].Algorithm, 0)
	clipboard.WriteAll(totp)
	left := period - time.Now().Unix()%period
	fmt.Fprintf(os.Stderr, green+"TOTP of "+yellow+"'"+name+"'"+green+" copied to clipboard, valid for"+yellow+" %d "+green+"s\n", left)
}

func showTotps(regex string, next bool) {
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for showing TOTPs")

	// Match regex and sort on name
	var names []string
	for name := range db.Entries {
		if match, _ := regexp.MatchString(regex, name); match {
			names = append(names, name)
		}
	}
	if redirected {
		for _, name := range names {
			totp := oneTimePassword(db.Entries[name].Secret, db.Entries[name].Digits, db.Entries[name].Algorithm, 0)
			ntotp := oneTimePassword(db.Entries[name].Secret, db.Entries[name].Digits, db.Entries[name].Algorithm, 1)
			tag := name
			if len(name) > maxNameLen {
				tag = name[:maxNameLen]
			}
			fmt.Printf("%v (%v) %v\n", totp, ntotp, tag)
		}
		return
	}

	nn := len(names)
	if nn == 0 {
		fmt.Fprintf(os.Stderr, red+"No entries")
		if regex != "" {
			fmt.Fprintln(os.Stderr, " matching Regex '"+regex+"'")
		}
		fmt.Fprintln(os.Stderr, def)
		return
	}

	// Check display capabilities
	w, h, _ := term.GetSize(int(os.Stdout.Fd()))
	cols, hdr, hdrspc := 0, "", ""
	if next {
		cols = (w + 1) / (8 + 1 + 8 + 1 + maxNameLen + 1)
		hdr = "   TOTP  nextTOTP - Name"
		hdrspc = fmt.Sprintf(strings.Repeat(" ", maxNameLen-6))
	} else {
		cols = (w + 1) / (8 + 1 + maxNameLen + 1)
		hdr = "   TOTP - Name"
		hdrspc = fmt.Sprintf(strings.Repeat(" ", maxNameLen-4))
	}
	if cols < 1 {
		exitOnError(errr, "Terminal too narrow to properly display entries")
	}

	if nn > cols*(h-1) {
		exitOnError(errr, "Terminal height too low, select fewer entries with REGEX")
	}

	sort.Strings(names)
	fmtstr := "%s %-" + fmt.Sprint(maxNameLen) + "s"
	for {
		fmt.Fprintf(os.Stderr, cls+blue+hdr)
		for i := 1; i < cols && i < nn; i++ {
			fmt.Fprintf(os.Stderr, hdrspc + hdr)
		}
		fmt.Fprintln(os.Stderr)
		n := 0
		for _, name := range names {
			totp := oneTimePassword(db.Entries[name].Secret, db.Entries[name].Digits, db.Entries[name].Algorithm, 0)
			totp = fmt.Sprintf("%8v", totp)
			tag := name
			if len(name) > maxNameLen {
				tag = name[:maxNameLen]
			}
			if next {
				ntotp := oneTimePassword(db.Entries[name].Secret, db.Entries[name].Digits, db.Entries[name].Algorithm, 1)
				ntotp = fmt.Sprintf("%8v", ntotp)
				fmt.Fprintf(os.Stderr, fmtstr, green+totp+magenta+ntotp+def, tag)
			} else {
				fmt.Fprintf(os.Stderr, fmtstr, green+totp+def, tag)
			}
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
				runtime.GC()
				os.Exit(0)
			}()
			time.Sleep(time.Second)
			left--
		}
	}
}

func showNames(regex string) {
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for showing Names")

	// Match regex and sort on name
	var names []string
	for name := range db.Entries {
		if match, _ := regexp.MatchString(regex, name); match {
			names = append(names, name)
		}
	}
	if len(names) == 0 && !redirected {
		fmt.Fprintf(os.Stderr, red+"No entries")
		if regex != "" {
			fmt.Fprintf(os.Stderr, " matching Regex '"+regex+"'")
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
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for showing Names")

	var otpauths []string
	for name := range db.Entries {
		line := fmt.Sprintf("otpauth://totp/%s?secret=%s&algorithm=%s&digits=%s&period=30&issuer=%s\n",
			url.PathEscape(name), string(db.Entries[name].Secret), db.Entries[name].Algorithm, db.Entries[name].Digits, url.PathEscape(name))
		otpauths = append(otpauths, line)
	}
	sort.Strings(otpauths)
	if filename == "" {
		for _, line := range otpauths {
			fmt.Printf("%s", line)
		}
	} else {
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			runtime.GC()
			exitOnError(err, "Cannot create file or file exists")
		}

		for _, line := range otpauths {
			_, err = f.WriteString(line)
			if err != nil {
				runtime.GC()
				exitOnError(err, "Error writing to "+filename)
			}
		}

		fmt.Fprintf(os.Stderr, "%sFile exported:%s %s\n", green, def, filename)
	}
	runtime.GC()
}

func importEntries(filename string) {
	file, err := os.Open(filename)
	exitOnError(err, "Could not open datafile '"+filename+"'")

	reader := bufio.NewScanner(file)
	reader.Split(bufio.ScanLines)
	db, err := readDb(false)
	exitOnError(err, "Failure opening datafile for import")

	// Check data, then admit to datafile, but only save when no errors
	n, ns, issuerseen := 0, "", false
	for reader.Scan() {
		var secret []byte
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

		name, err := url.PathUnescape(uri.Path[1:])
		exitOnError(err, "invalid NAME")
		if len(name) == 0 {
			exitOnError(errr, "NAME must have content on line "+ns)
		}

		if len(name) > maxNameLen {
			if force {
				fmt.Fprintf(os.Stderr, yellow+"WARNING"+def+": NAME longer than %d on line %d\n", maxNameLen, n)
			} else {
				exitOnError(errr, fmt.Sprintf("NAME longer than %d on line %d", maxNameLen, n))
			}
		}

		// NAME should not have a colon or percent sign
		if strings.Contains(name, ":") || strings.Contains(name, "%") {
			fmt.Fprintln(os.Stderr, red+"Entry '"+name+"' contains ':' or '%'")
			return
		}

		_, found := db.Entries[name]
		if found && !force {
			exitOnError(errr, "Entry '"+name+"' on line "+ns+" exists, force overwrite with -f/--force")
		}

		query, err := url.ParseQuery(uri.RawQuery)
		exitOnError(err, "Invalid Query part of URI")

		size, algorithm := "6", "SHA1"
		for key, value := range query {
			switch key {
			case "secret":
				if len(value) > 1 {
					exitOnError(errr, "Multiple SECRETs on line "+ns)
				}

				secret = checkBase32([]byte(value[0]))
				if len(secret) == 0 {
					exitOnError(err, "Invalid base32 encoding in SECRET on line "+ns)
				}

			case "period":
				if len(value) > 1 {
					exitOnError(errr, "Multiple PERIODs on line "+ns)
				}

				if value[0] != "30" {
					exitOnError(err, "Unsupported period (not 30) on line "+ns)
				}

			case "digits":
				if len(value) > 1 {
					exitOnError(errr, "Multiple TOTP LENGTHs (key 'digits') on line "+ns)
				}

				if size != "5" && size != "6" && size != "7" && size != "8" {
					exitOnError(errr, "TOTP LENGTH (key 'digits') on line "+ns+"not 5-8, but: "+value[0])
				}

			case "algorithm":
				if len(value) > 1 {
					exitOnError(errr, "Multiple HASHes (key 'algorithm') on line "+ns)
				}

				algorithm = strings.ToUpper(value[0])
				if algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512" {
					exitOnError(errr, "HASH (key 'algorithm') on line "+ns+"not SHA1/SHA256/SHA512, but: "+algorithm)
				}

			case "issuer":
				issuerseen = true
			default:
				fmt.Fprintf(os.Stderr, yellow+"WARNING"+def+": key '"+key+"' on line "+ns+" unsupported, "+red+"ignored\n"+def)
			}
		}
		if len(secret) == 0 {
			exitOnError(errr, "SECRET must be given on line "+ns)
		}

		db.Entries[name] = entry{
			Secret:    secret,
			Digits:    size,
			Algorithm: algorithm,
		}
	}
	file.Close()
	if issuerseen {
		fmt.Fprintf(os.Stderr, green+"INFO"+def+": key 'issuer' ignored\n"+def)
	}
	err = saveDb(&db)
	runtime.GC()
	exitOnError(err, "Failure saving datafile, entries not imported")

	fmt.Fprintf(os.Stderr, green+"All %d entries in '"+filename+"' successfully imported\n", n)
}

func main() {
	self, cmd, regex, datafile, name, nname, file := "", "", "", "", "", "", ""
	var secret []byte
	datafileflag, sizeflag, algorithmflag, size, algorithm, ddash, cas, next := 0, 0, 0, "6", "SHA1", false, false, false
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
		if datafileflag == 1 { // Previous argument was -d/--datafile
			datafile = arg
			datafileflag = 2
			continue
		}
		if sizeflag == 1 { // Previous argument was -s/--size
			size = arg
			sizeflag = 2
			continue
		}
		if algorithmflag == 1 { // Previous argument was -a/--algorithm
			algorithm = strings.ToUpper(arg)
			algorithmflag = 2
			continue
		}
		if !ddash {
			if arg == "--" {
				ddash = true
				continue
			}
			if arg == "-c" || arg == "--case" {
				cas = true
				continue
			}
			if arg == "-f" || arg == "--force" {
				force = true
				continue
			}
			if arg == "-n" || arg == "--next" {
				next = true
				continue
			}
			if arg == "-d" || arg == "--datafile" {
				if datafileflag > 0 {
					usage("datafile already specified with -d/--datafile")
				}
				datafileflag = 1
				continue
			}
			if arg == "-s" || arg == "--size" {
				if sizeflag > 0 {
					usage("size already specified with -s/--size")
				}
				sizeflag = 1
				continue
			}
			if arg == "-a" || arg == "--algorithm" {
				if algorithmflag > 0 {
					usage("algorithm already specified with -a/--algorithm")
				}
				algorithmflag = 1
				continue
			}
		}
		if cmd == "" { // Determine command (from arg1)
			switch arg { // First arg is command unless regex (arg1)
			case "help", "--help", "-h":
				usage("")
			case "version", "--version", "-V":
				fmt.Fprintln(os.Stderr, self+" version "+version)
				return

			case "show", "view":
				cmd = "s" // [REGEX]  [-c/--case]  [-n/--next]
			case "list", "ls":
				cmd = "l" // [REGEX]  [-c/--case]
			case "rename", "move", "mv":
				cmd = "m" // NAME  NEWNAME  [-f/--force]
			case "add", "insert", "entry":
				cmd = "a" // NAME  [SECRET]  [-s/--size LENGTH]  [-a/--algorithm HASH]  [-f/--force]
			case "totp", "temp":
				cmd = "t" // [SECRET]  [-s/--size LENGTH]  [-a/--algorithm HASH]  [-f/--force]
			case "reveal", "secret":
				cmd = "r" // NAME
			case "clip", "copy", "cp":
				cmd = "c" // NAME
			case "delete", "remove", "rm":
				cmd = "d" // NAME  [-f/--force]
			case "password", "passwd", "pw":
				cmd = "p" // none
			case "export":
				cmd = "e" // [FILE]
			case "import":
				cmd = "i" // FILE  [-f/--force]
			default: // No command, must be REGEX
				cmd, regex = "s", arg
			}
			continue
		}
		// self and cmd (or REGEX) and early flags && double-dash have been parsed
		switch cmd { // Parse rest of args based on cmd
		case "p":
			usage("password command takes no further arguments")
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
				force = true
				continue
			}
			if file != "" {
				usage("too many arguments, file FILE already given")
			}
			file = arg
		case "d":
			if !ddash && (arg == "-f" || arg == "--force") {
				force = true
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
				force = true
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
			if !ddash {
				if arg == "-f" || arg == "--force" {
					force = true
					continue
				}
				if arg == "-s" || arg == "--size" {
					sizeflag = 1
					continue
				}
				if arg == "-a" || arg == "--algorithm" {
					algorithmflag = 1
					continue
				}
			}
			if name != "" {
				if len(secret) > 0 {
					usage("too many arguments, NAME and SECRET already given")
				}
				secret = checkBase32([]byte(arg))
			} else {
				name = arg
			}
		case "t":
			if len(secret) > 0 {
				usage("too many arguments, SECRET already given")
			}
			secret = checkBase32([]byte(arg))
		}
	}
	// All arguments have been parsed, check
	if next && cmd != "" && cmd != "s" {
		usage("flag -n/--next can only be given on show/view command")
	}
	if cas && cmd != "" && cmd != "s" && cmd != "l" {
		usage("flag -c/--case can only be given on show/view and list/ls commands")
	}
	if datafileflag == 1 {
		usage("flag -d/--datafile needs a DATAFILE as argument")
	}
	if sizeflag == 1 {
		usage("flag -s/--size needs a LENGTH as argument")
	}
	if algorithmflag == 1 {
		usage("flag -a/--algorithm needs a HASH as argument")
	}
	if datafile != "" {
		dbPath = datafile
	}
	if regex != "" && !cas {
		regex = "(?i)"+regex
	}
	switch cmd {
	case "", "s":
		showTotps(regex, next)
	case "l":
		showNames(regex)
	case "a":
		if name == "" {
			usage("'add' command needs NAME as argument")
		}
		if len(secret) != 0 {
			addEntry(name, secret, size, algorithm, true)
		} else {
			addEntry(name, secret, size, algorithm, false)
		}
	case "t":
		showSingleTotp(secret, size, algorithm)
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
		clipTOTP(name)
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
	wipe(secret)
}

func usage(err string) {
	help := green + self + def + " v" + version + yellow + " - Manage TOTPs from CLI\n" +
		def + "The CLI is interactive & colorful, output to Stderr. Password can be piped in.\n" +
		"When output is redirected, only pertinent plain text is sent to Stdout.\n" +
		"* " + blue + "Repo" + def + ":       " + magenta + "github.com/pepa65/twofat" + def + " <pepa65@passchier.net>\n* " +
		blue + "Datafile" + def + ":   " + magenta + dbPath + def + "  (default, depends on the binary's name)\n* " +
		blue + "Usage" + def + ":      " + magenta + self + def + "  [" + green + "COMMAND" + def + "]  [ " + yellow + "-d" + def + " | " + yellow + "--datafile " + cyan + " DATAFILE" + def + " ]\n" +
		"  == " + green + "COMMAND" + def + ":\n" +
		"[ " + green + "show" + def + " | " + green + "view" + def + " ]  [" + blue + "REGEX" + def + " [ " + yellow + "-c" + def + " | " + yellow + "--case" + def + " ]]  [ " + yellow + "-n" + def + " | " + yellow + "--next" + def + " ]\n" +
		"    Display all TOTPs with " + blue + "NAME" + def + "s [matching " + blue + "REGEX" + def + "] (" + yellow + "-n" + def + "/" + yellow + "--next" + def + ": show next TOTP).\n" +
		green + "list" + def + " | " + green + "ls" + def + "  [" + blue + "REGEX" + def + " [ " + yellow + "-c" + def + " | " + yellow + "--case" + def + " ]]\n" +
		"    List all " + blue + "NAME" + def + "s [matching " + blue + "REGEX" + def + "].\n" +
		green + "add" + def + " | " + green + "insert" + def + " | " + green + "entry  " + blue + "NAME" + def + "  [" + yellow + "TOTP-OPTIONS" + def + "]  [ " + yellow + "-f" + def + " | " + yellow + "--force" + def + " ]  [" + blue + "SECRET" + def + "]\n" +
		"    Add a new entry " + blue + "NAME" + def + " with " + blue + "SECRET" + def + " (queried when not given).\n" +
		"    If " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": existing " + blue + "NAME" + def + " overwritten, no " + blue + "NAME" + def + " max.length check.\n" +
		green + "totp" + def + " | " + green + "temp" + def + "  [" + yellow + "TOTP-OPTIONS" + def + "]  [" + blue + "SECRET" + def + "]\n" +
		"    Show the TOTP for " + blue + "SECRET" + def + " (queried when not given), no datafile access.\n" +
		green + "delete" + def + " | " + green + "remove" + def + " | " + green + "rm  " + blue + "NAME" + def + "  [ " + yellow + "-f" + def + " | " + yellow + "--force" + def + " ]\n" +
		"    Delete entry " + blue + "NAME" + def + ". If " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": no confirmation asked.\n" +
		green + "rename" + def + " | " + green + "move" + def + " | " + green + "mv  " + blue + "NAME  NEWNAME" + def + "  [ " + yellow + "-f" + def + " | " + yellow + "--force" + def + " ]\n" +
		"    Rename entry " + blue + "NAME" + def + " to " + blue + "NEWNAME" + def + ", if " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": no max.length checks.\n" +
		green + "import  " + blue + "FILE" + def + "  [ " + yellow + "-f" + def + " | " + yellow + "--force" + def + " ]\n" +
		"    Import lines with OTPAUTH_URI from file " + blue + "FILE" + def + ".\n" +
		"    If " + yellow + "-f" + def + "/" + yellow + "--force" + def + ": existing " + blue + "NAME" + def + " overwritten, no " + blue + "NAME" + def + " max.length check.\n" +
		green + "export" + def + "  [" + blue + "FILE" + def + "]              Export " + magenta + "OTPAUTH_URI" + def + "-format entries [to file " + blue + "FILE" + def + "].\n" +
		green + "reveal" + def + " | " + green + "secret  " + blue + "NAME" + def + "       Show " + blue + "SECRET" + def + " of entry " + blue + "NAME" + def + ".\n" +
		green + "clip" + def + " | " + green + "copy" + def + " | " + green + "cp  " + blue + "NAME" + def + "      Put TOTP of entry " + blue + "NAME" + def + " onto the clipboard.\n" +
		green + "password" + def + " | " + green + "passwd" + def + " | " + green + "pw" + def + "      Change datafile encryption password.\n" +
		green + "version" + def + " | " + green + "--version" + def + " | " + green + "-V" + def + "    Show version.\n" +
		green + "help" + def + " | " + green + "--help" + def + " | " + green + "-h" + def + "          Show this help text.\n" +
		"  == " + blue + "REGEX" + def + ":  Optional, case-insensitive matching (unless " + yellow + "-c" + def + "/" + yellow + "--case" + def + " is given).\n" +
		"  == " + yellow + "TOTP-OPTIONS" + def + ":\n" +
		yellow + "-s" + def + " | " + yellow + "--size  " + cyan + "LENGTH" + def + "       TOTP length: " + cyan + "5" + def + "-" + cyan + "8" + def + " (default: " + cyan + "6" + def + ").\n" +
		yellow + "-a" + def + " | " + yellow + "--algorithm  " + cyan + "HASH" + def + "    Hash algorithm: " + cyan + "SHA1" + def + "/" + cyan + "SHA256" + def + "/" + cyan + "SHA512" + def +" (default: " + cyan + "SHA1" + def + ")."
	fmt.Fprintln(os.Stderr, help)
	if err != "" {
		fmt.Fprintln(os.Stderr, red+"Abort: "+err)
		os.Exit(5)
	}
	os.Exit(0)
}
