package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/urfave/cli"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	version = "0.2.0"
	maxNameLen = 25
)

var (
	errr = errors.New("Error")
	forceChange bool
	digits7 bool
	digits8 bool
	interrupt = make(chan os.Signal)
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
	return (uint32(bytes[0])<<24)+(uint32(bytes[1])<<16)+(uint32(bytes[2])<<8)+
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
	hashParts := hash[offset:offset+4]

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
		fmt.Println("Invalid base32 [only characters 2-7 and A-Z, spaces and dashes ignored]")
		return ""
	}
	return secret
}

func addEntry(name, secret string) {
	if len(name) == 0 {
		exitOnError(errr, "zero length entry name")
	}
	if len([]rune(name)) > maxNameLen {
		exitOnError(errr, fmt.Sprintf("name longer than %d", maxNameLen))
	}
	db, err := readDb()
	exitOnError(err, "Open data to manage entry failed")
	action := "Added"
	if _, found := db.Entries[name]; found {
		if !forceChange {
			fmt.Printf("Entry "+name+" already exists, sure to change? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadString('\n')
			if cfm[0] != 'y' {
				fmt.Println("Entry not changed")
				return
			}
		}
	}

	secret = checkBase32(secret)
	// If SECRET not supplied or invalid, ask for it
	reader := bufio.NewReader(os.Stdin)
	for len(secret) == 0 || err != nil {
		fmt.Println("Enter base32 secret [enter empty field to cancel]: ")
		secret, _ = reader.ReadString('\n')
		secret = strings.TrimSuffix(secret, "\n")
		secret = checkBase32(secret)
		if len(secret) == 0 {
			fmt.Println("Operation cancelled")
			return
		}
	}

	if digits7 && digits8 {
		exitOnError(errr, "Can't have both length 7 & 8")
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
			fmt.Printf("Sure to delete entry "+name+"? [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			cfm, _ := reader.ReadString('\n')
			if cfm[0] != 'y' {
				fmt.Println("Entry not deleted")
				return
			}
		}
		delete(db.Entries, name)
		err = saveDb(&db)
		exitOnError(err, "Failed to delete entry")
		fmt.Println("Entry "+name+" deleted")
	} else {
		fmt.Printf("Entry %s not found\n", name)
	}
}

func changePassword() {
	db, err := readDb()
	exitOnError(err, "Wrong password")
	fmt.Println("Changing password")
	err = initPassword(&db)
	exitOnError(err, "Failed to change password")
	saveDb(&db)
	fmt.Println("Password change successful")
}

func revealSecret(name string) {
	db, err := readDb()
	exitOnError(err, "Open database to reveal secret failed")
	secret := db.Entries[name].Secret
	if len(secret) == 0 {
		fmt.Printf("Entry %s not found\n", name)
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
	exitOnError(err, "Open database to clip code failed")
	if secret := db.Entries[name].Secret; len(secret) == 0 {
		fmt.Printf("Entry %s not found\n", name)
		return
	}
	code := oneTimePassword(db.Entries[name].Secret)
	code = code[len(code)-db.Entries[name].Digits:]
	clipboard.WriteAll(code)
	left := 30-time.Now().Unix()%30
	fmt.Printf("Code for %s put on the clipboard, valid for %ds\n", name, left)
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
			fmt.Printf(" matching regex '%s'", regex)
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
	fmtstr := " %8s  %-"+strconv.Itoa(maxNameLen)+"s"
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
		left := 30-time.Now().Unix()%30
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
	exitOnError(err, "Could not open filename "+filename)
	reader := csv.NewReader(bufio.NewReader(csvfile))
	db, err := readDb()
	exitOnError(err, "Open data to import entries failed")

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
		exitOnError(err, "error reading csv data on line "+ns)
		if len(line) != 3 {
			exitOnError(errr, "no 2 fields on line "+ns)
		}
		name = line[0]
		secret = line[1]
		digits, err = strconv.Atoi(line[2])
		exitOnError(err, "Not an integer on line "+ns+": "+line[2])
		if len(name) == 0 || len(secret) == 0 {
			exitOnError(errr, "empty field on line "+ns)
		}
		if len(name) > maxNameLen {
			exitOnError(errr,
					fmt.Sprintf("name longer than %d on line %d", maxNameLen, n))
		}
		if _, found := db.Entries[name]; found && !forceChange {
			exitOnError(errr, "entry "+name+" on line "+ns+
					" already exists, use -f to force")
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).
				DecodeString(strings.ToUpper(secret)); err != nil {
			exitOnError(err, "invalid base32 encoding on line "+ns)
		}
		if digits < 6 || digits > 8 {
			exitOnError(errr, "Digits not 6, 7 or 8 on line "+ns)
		}
		db.Entries[name] = entry{
			Secret: strings.ToUpper(secret),
			Digits: digits,
		}
	}
	saveDb(&db)
	fmt.Printf("All %d entries in %s successfully imported\n", n, filename)
	return
}

func main() {
	app := cli.NewApp()
	app.Name = self
	app.Usage = "Two Factor Authentication Tool"
	app.Description = "Manage a 2FA database from the commandline\n"+
		"   Database: "+dbPath
	app.Version = version
	app.Author = "github.com/pepa65/twofat"
	app.Email = "pepa65@passchier.net"
	app.UseShortOptionHandling = true
	app.Action = func(c *cli.Context) error {
		regex := ""
		if len(c.Args()) > 1 {
			return fmt.Errorf("Need at most 1 argument: REGEX\n")
		}
		if len(c.Args()) == 1 {
			regex = c.Args()[0]
		}
		showCodes(regex)
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name: "show",
			Aliases: []string{"view", "list", "ls"},
			UsageText: self+" [show|view|list|ls [REGEX]",
			Usage: "Show codes for all entries [that match REGEX]",
			Action: func(c *cli.Context) error {
				regex := ""
				if len(c.Args()) > 1 {
					return fmt.Errorf("Need at most 1 argument: REGEX\n")
				}
				if len(c.Args()) == 1 {
					regex = c.Args()[0]
				}
				showCodes(regex)
				return nil
			},
		}, {
			Name: "add",
			Aliases: []string{"insert", "entry"},
			UsageText: self+" add|insert|entry [-7|-8] [-f|--force] NAME [SECRET]",
			Usage: "Add a new entry NAME with SECRET",
			Action: func(c *cli.Context) error {
				secret := ""
				if len(c.Args()) < 1 {
					return fmt.Errorf("Need at least 1 argument: NAME\n")
				}
				if len(c.Args()) > 2 {
					return fmt.Errorf("Need at most 2 arguments: NAME & SECRET\n")
				}
				if len(c.Args()) == 2 {
					secret = c.Args()[1]
				}
				addEntry(c.Args()[0], secret)
				return nil
			},
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "f, force",
					Usage: "Force modification of existing entry",
					Destination: &forceChange,
				},
				cli.BoolFlag{
					Name: "7",
					Usage: "Code of length 7 instead of 6",
					Destination: &digits7,
				},
				cli.BoolFlag{
					Name: "8",
					Usage: "Code of length 8 instead of 6",
					Destination: &digits8,
				},
			},
		}, {
			Name: "secret",
			Aliases: []string{"reveal"},
			UsageText: self+" secret|reveal NAME",
			Usage: "Show secret of entry NAME",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					return fmt.Errorf("Need 1 argument: NAME\n")
				}
				revealSecret(c.Args()[0])
				return nil
			},
		}, {
			Name: "clip",
			Aliases: []string{"copy", "cp"},
			UsageText: self+" clip|copy|cp NAME",
			Usage: "Put code of entry NAME onto the clipboard",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					return fmt.Errorf("Need 1 argument: NAME\n")
				}
				clipCode(c.Args()[0])
				return nil
			},
		}, {
			Name: "delete",
			Aliases: []string{"remove", "rm"},
			UsageText: self+" delete|remove|rm [-f|--force] NAME",
			Usage: "Delete entry NAME",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					return fmt.Errorf("Need 1 argument: NAME\n")
				}
				deleteEntry(c.Args()[0])
				return nil
			},
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "f, force",
					Usage: "Force deletion, don't ask for confirmation",
					Destination: &forceChange,
				},
			},
		}, {
			Name: "password",
			Aliases: []string{"passwd", "pw"},
			UsageText: self+" password|pw",
			Usage: "Change password",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 0 {
					return fmt.Errorf("No arguments allowed\n")
				}
				changePassword()
				return nil
			},
		}, {
			Name: "import",
			Aliases: []string{"csv"},
			UsageText: self+" import|csv [-f|--force] CSVFILE",
			Usage: "Import entries 'NAME,SECRET,CODELENGTH' from CSVFILE",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					return fmt.Errorf("Need 1 argument: CSVFILE\n")
				}
				importEntries(c.Args()[0])
				return nil
			},
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "f, force",
					Usage: "Force modification of any existing entries",
					Destination: &forceChange,
				},
			},
		},
	}
	cli.HelpFlag = cli.BoolFlag{
		Name: "help, h",
		Usage: "Show this help, or use after a command for command help",
	}
	cli.VersionFlag = cli.BoolFlag{
		Name: "version, V, v",
		Usage: "Print version",
	}
	err := app.Run(os.Args)
	if err != nil {
		exitOnError(err, "Error")
	}
}
