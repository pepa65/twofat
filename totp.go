package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"os"
	"time"
)

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
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
			(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func OneTimePassword(keyStr string) (string, error) {
	byteSecret, err := base32.StdEncoding.WithPadding(base32.NoPadding).
			DecodeString(keyStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	value := toBytes(time.Now().Unix() / 30)

	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, byteSecret)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F
	number := toUint32(hashParts)
	return fmt.Sprintf("%08d", number), nil
}
