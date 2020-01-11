package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"strings"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"syscall"
	"encoding/gob"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/argon2"
)

const (
	aesKeySize uint32 = 32
	nonceSize = 12
	pwRetry = 3
)

var (
	self string
	dbPath string
	errWrongPassword = errors.New("password error")
)

type Entry struct {
	Secret string
	Digits int
}

type Db struct {
	Pwd []byte
	Entries map[string]Entry
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
	dbPath = path.Join(user.HomeDir, "." + self + ".enc")
}

func deriveKey(password []byte, salt []byte, hashLen uint32) (hashRaw []byte) {
	return argon2.IDKey(password, salt, 3, 65536, 4, hashLen)
}

func readDb() (Db, error) {
	var db Db
	if _, err := os.Stat(dbPath); err == nil {
		// Database file present
		dbdata, err := ioutil.ReadFile(dbPath)
		if err != nil || len(dbdata) < nonceSize+1 {
			return Db{}, errors.New("insufficient data in " + dbPath)
		}

		nonce := dbdata[:nonceSize]
		encdata := dbdata[nonceSize:]
		fmt.Printf("Enter password: ")
		db.Pwd, _ = terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		key := deriveKey(db.Pwd, nonce, aesKeySize)
		block, err := aes.NewCipher(key)
		if err != nil {
			return Db{}, errWrongPassword
		}
		aesGcm, err := cipher.NewGCM(block)
		if err != nil {
			return Db{}, errWrongPassword
		}
		decryptedData, err := aesGcm.Open(nil, nonce, encdata, nil)
		if err != nil {
			return Db{}, errWrongPassword
		}

		buf := bytes.NewBuffer(decryptedData)
		err = gob.NewDecoder(buf).Decode(&db.Entries)
		if err != nil {
			return Db{}, errors.New("invalid entry data")
		}
		return db, nil
	}

	// Database file not present
	os.MkdirAll(path.Dir(dbPath), 0700)
	fmt.Println("Initializing database file: " + dbPath)
	initPassword(&db)
	db.Entries = make(map[string]Entry)
	saveDb(&db)
	return db, nil
}

func saveDb(db *Db) error {
	var buf bytes.Buffer
	nonce := make([]byte, nonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return errors.New("Could not get randomized data")
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

func initPassword(db *Db) error {
	retryTimes := pwRetry
	for retryTimes > 0 {
		fmt.Printf("New password: ")
		pwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		if len(pwd) == 0 {
			fmt.Printf("\nPassword can't be empty")
		} else {
			fmt.Printf("\nConfirm password: ")
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
