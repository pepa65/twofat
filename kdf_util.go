package main

import (
	"golang.org/x/crypto/argon2"
)

func deriveKey(password []byte, salt []byte, hashLen uint32) (hashRaw []byte) {
	var times uint32 = 3
	var memCost uint32 = 65536
	var threads uint8 = 4
	return argon2.IDKey(password, salt, times, memCost, threads, hashLen)
}
