package main

import (
    "errors"

    "github.com/ebitengine/purego"
)


const (
	crypto_pwhash_SALTBYTES = 16
	crypto_pwhash_OPSLIMIT_INTERACTIVE = 2
	crypto_pwhash_MEMLIMIT_INTERACTIVE = 67108864 // 67 megabytes
	crypto_pwhash_ALG_ARGON2ID13 = 2
)

func crypto_pwhash(keyLen int, password []byte, salt []byte) ([]byte, error) {
    var crypto_pwhash_sodium func(out []byte, 
        outlen int, 
        passwd []byte, 
        passwdlen int, 
        salt []byte, 
        opslimit int, 
        memlimit int, 
        alg int,
    ) int
    purego.RegisterLibFunc(&crypto_pwhash_sodium, sodium, "crypto_pwhash")

    key := make([]byte, keyLen)
    v := crypto_pwhash_sodium(key, 
        keyLen, 
        password, 
        len(password), 
        salt, 
        crypto_pwhash_OPSLIMIT_INTERACTIVE, 
        crypto_pwhash_MEMLIMIT_INTERACTIVE, 
        crypto_pwhash_ALG_ARGON2ID13,
    )

    if v != 0 {
        return nil, errors.New("Out of memory")
    }

    return key, nil
}