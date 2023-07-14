package main

const (
	REPO_URL = "https://github.com/alexzava/krypto"

	SALT_SIZE = 16

	ARGON2_KEY_LEN = 32
	ARGON2_TIME = 4
	ARGON2_MEMORY =  1<<20
	ARGON2_THREADS = 4

	ENCRYPTION_KEY_LEN = 32

	HMAC_KEY_LEN = 32
	HMAC_TAG_LEN = 64
	
	BUFFER_SIZE = 1<<20

	KEK_CONTEXT = "ENCRYPTION_KEY"
	HMAC_KEY_CONTEXT = "HMAC_SHA3_KEY"

	SIGNATURE = "K<3"
	SIGNATURE_LEN = 3

	MODE_ENCRYPT = 0
	MODE_DECRYPT = 1
)