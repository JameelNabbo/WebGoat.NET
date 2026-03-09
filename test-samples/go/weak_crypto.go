package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/des"
	"fmt"
)

// VULN: Using MD5 for hashing (broken, collision attacks)
func hashPasswordMD5(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// VULN: Using SHA1 for hashing (deprecated for security)
func hashDataSHA1(data string) string {
	hash := sha1.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// VULN: Using DES encryption (deprecated, small key size)
func encryptDES(key, plaintext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

// VULN: MD5 used for file integrity check (insecure)
func checksumFile(data []byte) string {
	sum := md5.Sum(data)
	return fmt.Sprintf("%x", sum)
}
