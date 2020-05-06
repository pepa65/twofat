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
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	aesKeySize uint32 = 32
	nonceSize         = 12
	pwRetry           = 3
)

var (
	self             string
	dbPath           string
	errWrongPassword = errors.New("password error")
)

type entry struct {
	Secret string
	Digits int
}

type dbase struct {
	Pwd     []byte
	Entries map[string]entry
}

func init() {
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

func readDb() (dbase, error) {
	var db dbase
	if _, err := os.Stat(dbPath); err == nil {
		// Database file present
		dbdata, err := ioutil.ReadFile(dbPath)
		if err != nil || len(dbdata) < nonceSize+1 {
			return dbase{}, errors.New("insufficient data in " + dbPath)
		}

		nonce := dbdata[:nonceSize]
		encdata := dbdata[nonceSize:]
		fmt.Printf("Enter database password: ")
		db.Pwd, _ = terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
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
			return dbase{}, errors.New("invalid entry data")
		}
		return db, nil
	}

	// Database file not present
	os.MkdirAll(path.Dir(dbPath), 0700)
	fmt.Println("Initializing database file: " + dbPath)
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
		return errors.New("database write error")
	}
	return nil
}

func initPassword(db *dbase) error {
	retryTimes := pwRetry
	for retryTimes > 0 {
		fmt.Printf("New database password: ")
		pwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		if len(pwd) == 0 {
			fmt.Printf("\nPassword can't be empty")
		} else {
			fmt.Printf("\nConfirm database password: ")
			pwdc, _ := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if bytes.Equal(pwd, pwdc) {
				db.Pwd = pwd
				return nil
			}
			fmt.Printf("Passwords not the same")
		}
		retryTimes--
		if retryTimes > 0 {
			fmt.Printf(", retry")
		}
		fmt.Println()
	}
	return errWrongPassword
}
