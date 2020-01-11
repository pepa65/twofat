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
)

const (
	aesKeySize uint32 = 32
	nonceSize = 12
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

func readDb() (Db, error) {
	var db Db
	if _, err := os.Stat(dbPath); err == nil {
		dbdata, err := ioutil.ReadFile(dbPath)
		if err != nil || len(dbdata) < nonceSize+1 {
			return Db{}, errors.New("insufficient data in " + dbPath)
		}

		nonce := dbdata[:nonceSize]
		pwd := nonce
		pwdSet := dbdata[nonceSize]
		encdata := dbdata[nonceSize+1:]
		if pwdSet != 0 {
			fmt.Printf("Enter password: ")
			pwd, _ = terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
		}
		key := deriveKey(pwd, nonce, aesKeySize)
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
		if pwdSet == 0 {
			pwd = []byte("")
		}
		db.Pwd = pwd
		return db, nil
	}

	os.MkdirAll(path.Dir(dbPath), 0700)
	fmt.Println("Initializing database file " + dbPath)
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

	pwdSet := 0
	pwd := nonce
	if string(db.Pwd) != "" {
		pwdSet = 1
		pwd = db.Pwd
	}
	buf.Write(nonce)
	buf.WriteByte(byte(pwdSet))

	key := deriveKey(pwd, nonce, aesKeySize)
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
	retryTimes := 4
	for retryTimes > 0 {
		fmt.Printf("New password: ")
		newPwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\nConfirm password: ")
		confirmPwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if bytes.Equal(newPwd, confirmPwd) {
			db.Pwd = newPwd
			return nil
		}
		retryTimes--
		if retryTimes == 1 {
			fmt.Println("Not the same, last retry")
		} else {
			fmt.Println("Not the same, retry")
		}
	}
	return errWrongPassword
}
