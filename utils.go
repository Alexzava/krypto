package main

import (
	"unicode"
	"strings"
	"math/rand/v2"
	"encoding/base64"
	cryptoRand "crypto/rand"
)

func generateRandomPassword() string {
	var password string
	for i := 0; i < PASSWORD_DEFAULT_LEN; i++ {
		c := PASSWORD_GENERATOR_ALLOWED_CHARACTERS[rand.IntN(len(PASSWORD_GENERATOR_ALLOWED_CHARACTERS))]
		if i % 2 == 0 && unicode.IsLetter(rune(c)) {
			password += strings.ToUpper(string(c))
		} else {
			password += string(c)
		}
	}
	return password
}

func randomBytes(size int) []byte {
	rnd := make([]byte, size)
    _, err := cryptoRand.Read(rnd)
    if err != nil {
        panic(err)
    }
    return rnd
}

func toBase64String(bytes []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
}

func fromBase64(encodedStr string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encodedStr)
}