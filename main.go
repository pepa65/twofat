package main

import (
	"fmt"
	"os"
	"os/signal"
	"io"
	"bufio"
	"syscall"
	"time"
	"strings"
	"strconv"
	"sort"
	"errors"
	"encoding/base32"
	"github.com/urfave/cli"
	"github.com/atotto/clipboard"
	"encoding/csv"
)

const maxNameLen = 25

var (
	showOnce bool
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
		fmt.Println(errMsg + ": " + err.Error())
		os.Exit(1)
	}
}

func addEntry(name, secret string) error {
	if len(name) == 0 || len(secret) == 0 {
		exitOnError(errr, "invalid entry")
	}
	if len(name) > maxNameLen {
		exitOnError(errr, fmt.Sprintf("name longer than %d", maxNameLen))
	}
	db, err := readDb()
	exitOnError(err, "Open data to manage entry failed")
	action := "Added"
	if _, found := db.Entries[name]; found {
		if forceChange {
			action = "Changed"
		} else {
			exitOnError(errr, "entry " + name + " already exists, use -f to force")
		}
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).
			DecodeString(strings.ToUpper(secret)); err != nil {
		exitOnError(err, "invalid base32 encoding")
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
	db.Entries[name] = Entry{
		Secret: strings.ToUpper(secret),
		Digits: digits,
	}
	saveDb(&db)
	fmt.Printf("%s %s\n", action, name)
	return nil
}

func deleteEntry(name string) {
	db, err := readDb()
	exitOnError(err, "Open database to delete entry failed")
	if _, found := db.Entries[name]; found {
		delete(db.Entries, name)
		err = saveDb(&db)
		exitOnError(err, "Failed to delete entry")
		fmt.Println("Entry " + name + " deleted")
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
	fmt.Println("Password changed")
}

func revealSecret(name string) {
	db, err := readDb()
	exitOnError(err, "Open database to reveal secret failed")
	if secret := db.Entries[name].Secret; secret != "" {
		fmt.Printf("%s: %s\n", name, secret)
		fmt.Printf("[Ctrl+C to exit] ")
		<-interrupt
  } else {
    fmt.Printf("Entry %s not found\n", name)
	}
}

func clipCode(name string) {
	db, err := readDb()
	exitOnError(err, "Open database to clip code failed")
	code, err := OneTimePassword(db.Entries[name].Secret)
	exitOnError(err, "Can't generate code for " + name)
	code = code[len(code)-db.Entries[name].Digits:]
	clipboard.WriteAll(code)
	left := 30 - time.Now().Unix() % 30
	fmt.Printf("Code for %s put on the clipboard, valid for %ds/n", name, left)
}

func showCodes() {
	db, err := readDb()
	exitOnError(err, "Failed to read database")
	if len(db.Entries) == 0 {
		fmt.Println("No entries present")
		return
	}
	// Prepare sort on name
	names := make([]string, 0)
	for name := range db.Entries {
		names = append(names, name)
	}
	sort.Strings(names)

	fmtstr := " %8s  %-" + strconv.Itoa(maxNameLen) + "s"
	for true {
		if !showOnce {
			cls()
		}
		first := true
		for _, name := range names {
			code, err := OneTimePassword(db.Entries[name].Secret)
			exitOnError(err, "Can't generate code for " + name)
			code = code[len(code)-db.Entries[name].Digits:]
			fmt.Printf(fmtstr, code, name)
			if first {
				first = false
				fmt.Printf("    ")
			} else {
				fmt.Println()
				first = true
			}
		}
		left := 30 - time.Now().Unix() % 30
		for left > 0 {
			fmt.Printf("\rValidity: %2ds ", left)
			if showOnce {
				fmt.Println()
				return
			}
			fmt.Printf("   [Ctrl+C to exit] ")
			time.Sleep(time.Second)
			left--
		}
	}
	cls()
}

func importEntries(filename string) error {
	csvfile, err := os.Open(filename)
	exitOnError(err, "Could not open filename " + filename)
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
		exitOnError(err, "error reading csv data on line " + ns)
		if len(line) != 3 {
			exitOnError(errr, "no 2 fields on line " + ns)
		}
		name = line[0]
		secret = line[1]
		digits, err = strconv.Atoi(line[2])
		exitOnError(err, "Not an integer on line " + ns + ": " + line[2])
		if len(name) == 0 || len(secret) == 0 {
			exitOnError(errr, "empty field on line " + ns)
		}
		if len(name) > maxNameLen {
			exitOnError(errr,
					fmt.Sprintf("name longer than %d on line %d", maxNameLen, n))
		}
		if _, found := db.Entries[name]; found && !forceChange {
			exitOnError(errr, "entry " + name + " on line " + ns +
					" already exists, use -f to force")
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).
				DecodeString(strings.ToUpper(secret)); err != nil {
			exitOnError(err, "invalid base32 encoding on line " + ns)
		}
		if digits < 6 || digits > 8 {
			exitOnError(errr, "Digits not 6, 7 or 8 on line " + ns)
		}
		db.Entries[name] = Entry{
			Secret: strings.ToUpper(secret),
			Digits: digits,
		}
	}
	saveDb(&db)
	fmt.Printf("All %d entries in %s successfully imported\n", n, filename)
	return nil
}

func main() {
	// Handle Ctrl-C
	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT)
	go func() {
		<-interrupt
		cls()
		os.Exit(1)
	}()

	app := cli.NewApp()
	app.Name = "Two Factor Authentication Tool"
	app.Usage = "Manage a 2FA database from the commandline"
	app.Version = "0.1.2"
	app.UseShortOptionHandling = true
	app.Action = func(c *cli.Context) error {
		if len(c.Args()) != 0 {
			exitOnError(errr, "command not recognized")
		}
		showCodes()
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name: "show",
			UsageText: "twofat [show] [-o|--once]",
			Usage: "Show codes for all entries",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 0 {
					exitOnError(errr, "No arguments allowed")
				}
				showCodes()
				return nil
			},
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "o, once",
					Usage: "Just show current codes once",
					Destination: &showOnce,
				},
			},
		}, {
			Name: "add",
			UsageText: "twofat add [-7|-8] NAME SECRET",
			Usage: "Add a new entry NAME with SECRET",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 2 {
					exitOnError(errr, "need 2 arguments: NAME & SECRET")
				}
				addEntry(c.Args().First(), c.Args()[1])
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
			UsageText: "twofat secret NAME",
			Usage: "Show secret of entry NAME",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					exitOnError(errr, "need 1 argument: NAME")
				}
				revealSecret(c.Args().First())
				return nil
			},
		}, {
			Name: "clip",
			UsageText: "twofat clip NAME",
			Usage: "Put code of entry NAME onto the clipboard",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					exitOnError(errr, "need 1 argument: NAME")
				}
				clipCode(c.Args().First())
				return nil
			},
		}, {
			Name: "delete",
			UsageText: "twofat delete NAME",
			Usage: "Delete entry NAME",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					exitOnError(errr, "need 1 argument: NAME")
				}
				deleteEntry(c.Args().First())
				return nil
			},
		}, {
			Name: "password",
			UsageText: "twofat password",
			Usage: "Change password",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 0 {
					exitOnError(errr, "no arguments allowed")
				}
				changePassword()
				return nil
			},
		}, {
			Name: "import",
			UsageText: "twofat import FILENAME.CSV",
			Usage: "Import entries 'NAME,SECRET,CODELENGTH' from CSV file",
			Action: func(c *cli.Context) error {
				if len(c.Args()) != 1 {
					exitOnError(errr, "need 1 argument: FILENAME.CSV")
				}
				importEntries(c.Args().First())
				return nil
			},
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "f, force",
					Usage: "Force modification of existing entries",
					Destination: &forceChange,
				},
			},
		},
	}

	cli.HelpFlag = cli.BoolFlag{
		Name: "help, h",
		Usage: "Show this help",
	}

	cli.VersionFlag = cli.BoolFlag{
		Name: "version, V",
		Usage: "Print version",
	}

	err := app.Run(os.Args)
	if err != nil {
		exitOnError(err, "Error")
	}
}
