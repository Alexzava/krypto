package main

import (
	"fmt"
	"io"
	"os"
	"log"
	"strings"
	"errors"

	"path/filepath"
	"crypto/rand"
	"crypto/aes"
	"crypto/hmac"
	"crypto/cipher"
	
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

var (
	PRINT_LOG = true
)

type FileHeader struct {
	Tag []byte
    KeySalt []byte
   	IV []byte
}

// Generate key from password
// Alg: Argon2id
// return []byte
func DeriveKeyFromPassword(password []byte, keyLen int, salt []byte) []byte {
	key := argon2.IDKey(password, salt, ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS, uint32(keyLen))
	return key
}

// Read header data from a file
// return FileHeader{}
func ReadFileHeader(inputFile string) FileHeader {
	var header FileHeader

	inFile, err := os.Open(inputFile)
	if err != nil {
		log.Println(err)
	}
	defer inFile.Close()

	// Skip signature
	inFile.Seek(SIGNATURE_LEN, 0)

	// Read Tag, KeySalt and IV from file
	readHeader := make([]byte, HMAC_TAG_LEN + SALT_SIZE + aes.BlockSize)
	_, err = inFile.Read(readHeader)
	if err != nil {
		log.Println(err)
	}

	header.Tag = readHeader[:HMAC_TAG_LEN]
	header.KeySalt = readHeader[HMAC_TAG_LEN:HMAC_TAG_LEN + SALT_SIZE]
	header.IV = readHeader[HMAC_TAG_LEN + SALT_SIZE:]

	return header
}

// Generate a new header with random values
// return FileHeader {}
func CreateFileHeader() FileHeader {
	var header FileHeader
	header.KeySalt = RandomBytes(SALT_SIZE)
	header.IV = RandomBytes(aes.BlockSize)
	header.Tag = make([]byte, HMAC_TAG_LEN)

	return header
}

// Encrypt or decrypt a file
func ProcessFile(opMode int, inputFile, outputDir string, header FileHeader, key []byte, progress *float64, logStatus *string) error {
	if opMode != MODE_ENCRYPT && opMode != MODE_DECRYPT {
		return errors.New("Invalid operation mode")
	}

	if len(key) != ARGON2_KEY_LEN {
		return errors.New("Invalid key size")
	}

	if len(header.KeySalt) != SALT_SIZE {
		return errors.New("Invalid salt size")
	}

	if len(header.IV) != aes.BlockSize {
		return errors.New("Invalid iv size")
	}

	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	fileInfo, err := inFile.Stat()
	if err != nil {
		return err
	}
	fileName := fileInfo.Name()
	fileSize := fileInfo.Size()

	if opMode == MODE_ENCRYPT {
		fileName = fileName + ".enc"
	} else {
		fileName = strings.ReplaceAll(fileName, ".enc", "")
	}

	// Derive encryption key and hmac key
	kek := make([]byte, ENCRYPTION_KEY_LEN)
	hmacKey := make([]byte, HMAC_KEY_LEN)

	prk := hkdf.Extract(sha3.New512, key, header.KeySalt)
	hkdf.Expand(sha3.New512, prk, []byte(KEK_CONTEXT)).Read(kek)
	hkdf.Expand(sha3.New512, prk, []byte(HMAC_KEY_CONTEXT)).Read(hmacKey)

    // HMAC Tag
	tag := hmac.New(sha3.New512, hmacKey)
	tag.Write(header.KeySalt)
	tag.Write(header.IV)

    // Verify hmac tag
    if opMode == MODE_DECRYPT {
    	if PRINT_LOG {
			fmt.Println("Verifying tag...")
			*logStatus = "Verifying tag..."
		}

    	inFile.Seek(SIGNATURE_LEN + HMAC_TAG_LEN + SALT_SIZE + aes.BlockSize, 0)
    	
		buffer := make([]byte, BUFFER_SIZE)
		status := 0
		for {
			bytesread, err := inFile.Read(buffer)
			if err != nil {
				if err != io.EOF {
					return err
				}
				break
			}
			status += bytesread

			tag.Write(buffer[:bytesread])

			if PRINT_LOG {
				fmt.Sprintf("\r%d%%", (status * 100 / int(fileSize)))
				*progress = float64(status * 100 / int(fileSize))
				//logStatus = fmt.Sprintf("Verifying tag... %d%%", (status * 100 / int(fileSize)))
			}
		}
		if PRINT_LOG {
			fmt.Println("OK")
			*logStatus = "OK"
		}
		
		if !hmac.Equal(tag.Sum(nil), header.Tag) {
			return errors.New("Tags does not match")
		}

		inFile.Seek(SIGNATURE_LEN + HMAC_TAG_LEN + SALT_SIZE + aes.BlockSize, 0)
    }

    // AES-CTR cipher
    block, err := aes.NewCipher(kek)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, header.IV)

    // Create output file
    outputFile := outputDir + "\\" + fileName
    if outputDir == "" {
    	outputFile = filepath.Dir(inputFile) + "\\" + fileName
    }

    outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
	    return err
	}
	defer outFile.Close()

	if opMode == MODE_ENCRYPT {
		// Allocate tag bytes + signature bytes
		placeholder := make([]byte, SIGNATURE_LEN + HMAC_TAG_LEN)
		if _, err := outFile.Write(placeholder); err != nil {
			outFile.Close()
			return err
		}

		// Write KeySalt and IV to output file
		if _, err := outFile.Write(append(header.KeySalt, header.IV...)); err != nil {
			outFile.Close()
			return err
		}
	}

	// Read and krypt file
	*logStatus = "Processing file..."
	buffer := make([]byte, BUFFER_SIZE)
	status := 0
	for {
		bytesread, err := inFile.Read(buffer)
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		status = status + bytesread

		kryptBuffer := make([]byte, bytesread)
		stream.XORKeyStream(kryptBuffer, buffer[:bytesread])

		if _, err := outFile.Write(kryptBuffer); err != nil {
			return err
		}

		if opMode == MODE_ENCRYPT {
			tag.Write(kryptBuffer)
		}

		if PRINT_LOG {
			fmt.Printf("\r%d%%", (status * 100 / int(fileSize)))
			*progress = float64(status * 100 / int(fileSize))
		}
	}
	outFile.Close()

	if opMode == MODE_ENCRYPT {
		// Calculate tag hash
		header.Tag = tag.Sum(nil)

		// Add tag and signature to output file
		outFile, err = os.OpenFile(outputFile, os.O_WRONLY, 0600)
		if err != nil {
		    return err
		}
		defer outFile.Close()

		if _, err := outFile.Write(append([]byte(SIGNATURE), header.Tag...)); err != nil {
			return err
		}
		outFile.Close()
	}

	if PRINT_LOG {
		fmt.Printf("\nResult in %s", outputFile)
		*logStatus = outputFile
		*progress = 100
	}

	return nil
}

// Overwrite file with random bytes then delete
func OverwriteFile(input string, progress *float64, logStatus *string) error {
	fileInfo, err := os.Stat(input)
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()
	wBytes := int64(0)
	buffer := make([]byte, BUFFER_SIZE)

	if int64(len(buffer)) > fileSize {
		buffer = make([]byte, fileSize)
	}

	targetFile, err := os.OpenFile(input, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer targetFile.Close()

	*logStatus = "Deleting file"
	for {
		_, err := rand.Read(buffer)
		if err != nil {
			return err
		}

		if _, err := targetFile.Write(buffer); err != nil {
			return err
		}

		wBytes = wBytes + int64(len(buffer))

		if wBytes >= fileSize {
			targetFile.Close()
			break
		}

		if wBytes + int64(len(buffer)) > fileSize {
			len := (wBytes + int64(len(buffer))) - fileSize
			buffer = make([]byte, len)
		}

		if PRINT_LOG {
			fmt.Printf("\r%d%%", (wBytes * 100 / fileSize))
			*progress = float64(wBytes * 100 / fileSize)
		}
	}
	os.Remove(input)

	if PRINT_LOG {
		fmt.Printf("File removed")
		*logStatus = "File removed"
		*progress = 100
	}

	return nil
}

// Generate secure random bytes
// return []byte
func RandomBytes(size int) []byte {
	rnd := make([]byte, size)
	_, err := rand.Read(rnd)
	if err != nil {
		log.Fatal(err)
	}
	return rnd
}