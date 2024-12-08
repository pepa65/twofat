package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	aesKeySize uint32 = 32
	nonceSize         = 12
	pwRetry           = 3
	cls               = "\033c"
	red               = "\033[1;31m"
	green             = "\033[1;32m"
	yellow            = "\033[1;33m"
	blue              = "\033[1;34m"
	magenta           = "\033[1;35m"
	cyan              = "\033[1;36m"
	def               = "\033[0m"
)

var (
	self             string
	dbPath           string
	errWrongPassword = errors.New("password error")
)

type entry struct { // v2.x.y
	Secret    []byte
	Digits    string
	Algorithm string
}

type entryV1 struct { // v1.x.y
	Secret    string
	Digits    string
	Algorithm string
}

type entryV0 struct { // v0.x.y
	Secret    string
	Digits    int
}

type dbase struct {
	Pwd     []byte
	Entries map[string]entry
	EntriesV1 map[string]entryV1
	EntriesV0 map[string]entryV0
}

func init() {
	if dbPath != "" {
		return
	}

	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	self = os.Args[0]
	i := strings.IndexByte(self, '/')
	for i >= 0 {
		self = self[i+1:]
		i = strings.IndexByte(self, '/')
	}
	dbPath = path.Join(user.HomeDir, "."+self+".enc")
}

func deriveKey(password []byte, salt []byte, hashLen uint32) (hashRaw []byte) {
	return argon2.IDKey(password, salt, 3, 65536, 4, hashLen)
}

func readDb(clearscr bool) (dbase, error) {
	if clearscr {
		fmt.Fprintf(os.Stderr, cls)
	}
	var db dbase
	if _, err := os.Stat(dbPath); err == nil {
		// Datafile file present
		dbdata, err := ioutil.ReadFile(dbPath)
		if err != nil || len(dbdata) < nonceSize+1 {
			return dbase{}, errors.New("insufficient data in " + dbPath)
		}

		nonce := dbdata[:nonceSize]
		encdata := dbdata[nonceSize:]
		if !redirected {
			fmt.Fprintln(os.Stderr, "Datafile: "+blue+dbPath+def)
		}
		if !term.IsTerminal(0) { // Piped in
			db.Pwd, _ = io.ReadAll(os.Stdin)
		}
		if len(db.Pwd) == 0 {
			fmt.Fprintf(os.Stderr, yellow+"Enter datafile password: "+def)
			db.Pwd, _ = term.ReadPassword(0)
			fmt.Fprintln(os.Stderr)
		}
		key := deriveKey(db.Pwd, nonce, aesKeySize)
		block, err := aes.NewCipher(key)
		if err != nil {
			return dbase{}, errWrongPassword
		}

		aesGcm, err := cipher.NewGCM(block)
		if err != nil {
			return dbase{}, errWrongPassword
		}

		decryptedData, err := aesGcm.Open(nil, nonce, encdata, nil)
		if err != nil {
			return dbase{}, errWrongPassword
		}

		buf := bytes.NewBuffer(decryptedData)
		err = gob.NewDecoder(buf).Decode(&db.Entries)
		if err != nil {
			buf = bytes.NewBuffer(decryptedData)
			err = gob.NewDecoder(buf).Decode(&db.EntriesV1)
			if err == nil {
				fmt.Fprintln(os.Stderr, cyan+"Export the contents of this v1 datafile with 'twofat' version 1.0.0 or 1.0.1\nand import the exported data with twofat v2.0.0 or later.")
				os.Exit(1)
			}
			buf = bytes.NewBuffer(decryptedData)
			err = gob.NewDecoder(buf).Decode(&db.EntriesV0)
			if err == nil {
				fmt.Fprintln(os.Stderr, cyan+"Export the contents of this v0 datafile with 'twofat' version 0.11.0 or earlier\nand import the exported data with twofat v2.0.0 or later.")
				os.Exit(1)
			}
			return dbase{}, errors.New("invalid entries data")
		}

		return db, nil
	}

	// Database file not present
	os.MkdirAll(path.Dir(dbPath), 0700)
	fmt.Fprintln(os.Stderr, green+"Initializing datafile"+def)
	initPassword(&db)
	db.Entries = make(map[string]entry)
	saveDb(&db)
	return db, nil
}

func saveDb(db *dbase) error {
	var buf bytes.Buffer
	nonce := make([]byte, nonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return errors.New("could not get randomized data")
	}

	buf.Write(nonce)
	key := deriveKey(db.Pwd, nonce, aesKeySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return errWrongPassword
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return errWrongPassword
	}

	var gobBuf bytes.Buffer
	err = gob.NewEncoder(&gobBuf).Encode(db.Entries)
	if err != nil {
		return errors.New("problem encoding data")
	}

	encryptedData := aesGcm.Seal(nil, nonce, gobBuf.Bytes(), nil)
	buf.Write(encryptedData)
	err = ioutil.WriteFile(dbPath, buf.Bytes(), 0600)
	if err != nil {
		return errors.New("datafile write error")
	}

	return nil
}

func initPassword(db *dbase) error {
	retryTimes := pwRetry
	fmt.Fprintln(os.Stderr, "Datafile: "+blue+dbPath+def)
	for retryTimes > 0 {
		fmt.Fprintf(os.Stderr, yellow+"New datafile password: ")
		pwd, _ := term.ReadPassword(0)
		if len(pwd) == 0 {
			fmt.Fprintf(os.Stderr, red+"\nPassword can't be empty")
		} else {
			fmt.Fprintf(os.Stderr, "\nConfirm datafile password: ")
			pwdc, _ := term.ReadPassword(0)
			fmt.Fprintln(os.Stderr, def)
			if bytes.Equal(pwd, pwdc) {
				db.Pwd = pwd
				wipe(pwdc)
				return nil
			}

			fmt.Fprintf(os.Stderr, red+"Passwords not the same")
		}
		retryTimes--
		if retryTimes > 0 {
			fmt.Fprintf(os.Stderr, ", retry")
		}
		fmt.Fprintln(os.Stderr, def)
	}
	return errWrongPassword
}
