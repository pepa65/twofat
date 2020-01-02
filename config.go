package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	DbPath = ".twofat.enc"
	aesKeySize uint32 = 32
	nonceSize = 12
)

type Entry struct {
	Secret string
	Digits int
}

type Db struct {
	Pwd []byte
	Entries map[string]Entry
}

var (
	dbPath = ""
	errWrongPassword = errors.New("password error")
)

func init() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	dbPath = path.Join(usr.HomeDir, DbPath)
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
		encdata := dbdata[nonceSize+1:]
		if dbdata[nonceSize] != 0 {
			fmt.Printf("Enter password: ")
			pwd, _ = terminal.ReadPassword(int(syscall.Stdin))
			fmt.Printf("\r                \r")
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
		return db, nil
	}

	os.MkdirAll(path.Dir(dbPath), 0700)
	fmt.Println("Initializing database file")
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
		return errors.New("Could not get random data")
	}

	buf.Write(nonce)
	pwdSet := 0
	if len(db.Pwd) != 0 {
		pwdSet = 1
	}
	buf.WriteByte(byte(pwdSet))

	pwd := nonce
	if string(db.Pwd) != "" {
		pwd = db.Pwd
	}

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
