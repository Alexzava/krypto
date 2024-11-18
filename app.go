package main

import (
	"io"
	"os"
	"bytes"
	"context"
	"strings"
	"path/filepath"
	"encoding/base64"

	"github.com/skip2/go-qrcode"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// Open file picker dialog
func (a *App) ShowFilePickerDialog() string {
	file, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{})
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return ""
	}

	if file == "" {
		logMessage("Canceled", a.ctx)
		return ""
	}

	logMessage("File selected", a.ctx)
	return file
}

// Generate new random key pair
func (a *App) GenerateKeyPair() []string {
	publicKey, privateKey := crypto_kx_keypair()
	return []string {
		toBase64String(publicKey), 
		toBase64String(privateKey),
	}
}

// Export private key to file
func (a *App) ExportPrivateKey(privateKey string) bool {
	file, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: "private.key",
	})
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	if file == "" {
		logMessage("Canceled", a.ctx)
		return false
	}

    privateKeyBytes, err := fromBase64(privateKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	if len(privateKeyBytes) != crypto_kx_SECRETKEYBYTES {
		logMessage("Invalid private key", a.ctx)
		return false
	}

	f, err := os.Create(file)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	defer f.Close()

	_, err = f.WriteString(privateKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	f.Close()

	return true
}

// Read private key from file
func (a *App) ImportPrivateKey() string {
	fileName, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{})
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return ""
	}
	if fileName == "" {
		logMessage("Canceled", a.ctx)
		return ""
	}
	
	keyFile, err := os.Open(fileName)
    if err != nil {
        logMessage(err.Error(), a.ctx)
        return ""
    }
    defer keyFile.Close()

    privateKey, err := io.ReadAll(keyFile)
    if err != nil {
    	logMessage(err.Error(), a.ctx)
        return ""
    }

    privateKeyBytes, err := fromBase64(string(privateKey))
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return ""
	}

	if len(privateKeyBytes) != crypto_kx_SECRETKEYBYTES {
		logMessage("Invalid private key", a.ctx)
		return ""
	}

    return string(privateKey)
}

// Generate a share link
func (a *App) GenerateShareLink(isExtLink bool, publicKey string) string {
	publicKeyBytes, err := fromBase64(publicKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return ""
	}

	if len(publicKeyBytes) != crypto_kx_PUBLICKEYBYTES {
		logMessage("Invalid public key", a.ctx)
		return ""
	}

	return generateShareLink(isExtLink, publicKey)
}

// Generate a share QR Code
func (a *App) GenerateShareQRCode(isExtLink bool, publicKey string) string {
	publicKeyBytes, err := fromBase64(publicKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return ""
	}
	
	if len(publicKeyBytes) != crypto_kx_PUBLICKEYBYTES {
		logMessage("Invalid public key", a.ctx)
		return ""
	}

	var png []byte
  	png, err = qrcode.Encode(generateShareLink(isExtLink, publicKey), qrcode.Medium, 256)
  	if err != nil {
  		logMessage(err.Error(), a.ctx)
  		return ""
  	}
  	return base64.StdEncoding.EncodeToString(png)
}

// Generate a random password
func (a *App) GenerateRandomPassword() string {
	return generateRandomPassword()
}

// Open Krypto repository on system browser
func (a *App) OpenRepository() {
	runtime.BrowserOpenURL(a.ctx, LINK_REPO)
}

// Encrypt with password
func (a *App) EncryptSymmetric(password string, inputFile string) bool {
	if len(password) < PASSWORD_LEN_MIN {
		logMessage("Password is too short", a.ctx)
		return false
	}

	keySalt := randomBytes(crypto_pwhash_SALTBYTES)
	key, err := crypto_pwhash(crypto_secretstream_xchacha20poly1305_KEYBYTES, []byte(password), keySalt)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	return processFile(key, keySalt, inputFile, MODE_PASSWORD, ACTION_ENCRYPT, a.ctx)
}

// Decrypt with password
func (a *App) DecryptSymmetric(password string, inputFile string) bool {
	keySalt := make([]byte, crypto_pwhash_SALTBYTES)

	if len(password) == 0 {
		logMessage("Invalid password", a.ctx)
		return false
	}

	// Read salt from file
	inFile, err := os.Open(inputFile)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	defer inFile.Close()

	inFile.Seek(SIGNATURE_SYMMETRIC_LEN, 0)

	_, err = inFile.Read(keySalt)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}

	key, err := crypto_pwhash(crypto_secretstream_xchacha20poly1305_KEYBYTES, []byte(password), keySalt)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}

	return processFile(key, keySalt, inputFile, MODE_PASSWORD, ACTION_DECRYPT, a.ctx)
}

// Encrypt with shared secret key
func (a *App) EncryptAsymmetric(personalPrivateKey, recipientPublicKey string, inputFile string) bool {
	privateKeyBytes, err := fromBase64(personalPrivateKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}

	publicKeyBytes, err := fromBase64(recipientPublicKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}

	if !checkKeys(privateKeyBytes, publicKeyBytes) {
		logMessage("Invalid keys", a.ctx)
		return false
	}

	_, tx, err := crypto_kx_client_session_keys(crypto_scalarmult_base(privateKeyBytes), privateKeyBytes, publicKeyBytes)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	return processFile(tx, make([]byte, 0), inputFile, MODE_PUBLIC_KEY, ACTION_ENCRYPT, a.ctx)
}

// Decrypt with shared secret key
func (a *App) DecryptAsymmetric(personalPrivateKey, recipientPublicKey string, inputFile string) bool {
	privateKeyBytes, err := fromBase64(personalPrivateKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}

	publicKeyBytes, err := fromBase64(recipientPublicKey)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}

	if !checkKeys(privateKeyBytes, publicKeyBytes) {
		logMessage("Invalid Keys", a.ctx)
		return false
	}

	rx, _, err := crypto_kx_server_session_keys(crypto_scalarmult_base(privateKeyBytes), privateKeyBytes, publicKeyBytes)
	if err != nil {
		logMessage(err.Error(), a.ctx)
		return false
	}
	return processFile(rx, make([]byte, 0), inputFile, MODE_PUBLIC_KEY, ACTION_DECRYPT, a.ctx)
}

// Encrypt or Decrypt file
func processFile(key []byte, keySalt []byte, inputFile string, passwordMode string, opMode string, ctx context.Context) bool {
	if opMode != ACTION_ENCRYPT && opMode != ACTION_DECRYPT {
		logMessage("Invalid operation mode", ctx)
		return false
	}

	if passwordMode != MODE_PASSWORD && passwordMode != MODE_PUBLIC_KEY {
		logMessage("Invalid key mode", ctx)
		return false
	}

	if len(key) != crypto_secretstream_xchacha20poly1305_KEYBYTES {
		logMessage("Invalid key size", ctx)
		return false
	}

	if passwordMode == MODE_PASSWORD && len(keySalt) != crypto_pwhash_SALTBYTES {
		logMessage("Invalid salt size", ctx)
		return false
	}

	// Output file name
	var outputFileName string
	if opMode == ACTION_ENCRYPT {
		outputFileName = filepath.Base(inputFile) + ".enc"
	} else {
		outputFileName = strings.ReplaceAll(filepath.Base(inputFile), ".enc", "")
	}
	
	// Ask output file save location
	outputFilePath, err := runtime.SaveFileDialog(ctx, runtime.SaveDialogOptions{
		DefaultDirectory: filepath.Dir(inputFile),
		DefaultFilename: outputFileName,
	})
	if err != nil {
		logMessage(err.Error(), ctx)
		return false
	}
	if outputFilePath == "" {
		logMessage("Canceled", ctx)
		return false
	}

	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		logMessage(err.Error(), ctx)
		return false
	}
	defer inFile.Close()

	fileInfo, err := inFile.Stat()
	if err != nil {
		logMessage(err.Error(), ctx)
		return false
	}
	fileSize := fileInfo.Size()

	// Create output file
	outFile, err := os.OpenFile(outputFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
	    logMessage(err.Error(), ctx)
	    return false
	}
	defer outFile.Close()

	// Init header and secret stream
	var state Crypto_secretstream_xchacha20poly1305_state
	header := make([]byte, crypto_secretstream_xchacha20poly1305_HEADERBYTES)
	if opMode == ACTION_ENCRYPT {
		state, header = crypto_secretstream_xchacha20poly1305_init_push(key)
	} else {
		// Read header from file
		if passwordMode == MODE_PASSWORD {
			inFile.Seek(SIGNATURE_SYMMETRIC_LEN + crypto_pwhash_SALTBYTES, 0)
		} else {
			inFile.Seek(SIGNATURE_ASYMMETRIC_LEN, 0)
		}

		_, err = inFile.Read(header)
		if err != nil {
			logMessage(err.Error(), ctx)
			return false
		}

		state, err = crypto_secretstream_xchacha20poly1305_init_pull(header, key)
		if err != nil {
			logMessage(err.Error(), ctx)
			return false
		}
	}

	// Add Signature, Salt and Header to output stream
	if opMode == ACTION_ENCRYPT {
		if passwordMode == MODE_PASSWORD {
			if _, err := outFile.Write(append([]byte(SIGNATURE_SYMMETRIC), keySalt...)); err != nil {
				outFile.Close()
				logMessage(err.Error(), ctx)
				return false
			}
		} else {
			if _, err := outFile.Write([]byte(SIGNATURE_ASYMMETRIC)); err != nil {
				outFile.Close()
				logMessage(err.Error(), ctx)
				return false
			}
		}

		if _, err := outFile.Write(header); err != nil {
			outFile.Close()
			logMessage(err.Error(), ctx)
			return false
		}
	}

	var bufferSize int
	if opMode == ACTION_ENCRYPT {
		bufferSize = CHUNK_SIZE
	} else {
		bufferSize = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES
	}
	buffer := make([]byte, bufferSize)

	status := 0
	for {
		bytesread, err := inFile.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logMessage(err.Error(), ctx)
				return false
			}
			break
		}
		status = status + bytesread

		var outputBuffer []byte
		if bytesread < bufferSize {
			if opMode == ACTION_ENCRYPT {
				outputBuffer = crypto_secretstream_xchacha20poly1305_push(state, buffer[:bytesread], crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			} else {
				outputBuffer, err = crypto_secretstream_xchacha20poly1305_pull(state, buffer[:bytesread], []byte{ crypto_secretstream_xchacha20poly1305_TAG_FINAL })
				if err != nil {
					logMessage(err.Error(), ctx)
					// Cancel operation, delete output file
					outFile.Close()
					os.Remove(outputFilePath)
					return false
				}
			}
		} else {
			if opMode == ACTION_ENCRYPT {
				outputBuffer = crypto_secretstream_xchacha20poly1305_push(state, buffer, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
			} else {
				outputBuffer, err = crypto_secretstream_xchacha20poly1305_pull(state, buffer, []byte{ crypto_secretstream_xchacha20poly1305_TAG_MESSAGE })
				if err != nil {
					logMessage(err.Error(), ctx)
					// Cancel operation, delete output file
					outFile.Close()
					os.Remove(outputFilePath)
					return false
				}
			}
		}

		if _, err := outFile.Write(outputBuffer); err != nil {
			logMessage(err.Error(), ctx)
			return false
		}

		// Update progress
		progress := int64(status * 100) / fileSize
		runtime.EventsEmit(ctx, "progress", progress)
	}
	outFile.Close()
	inFile.Close()
	runtime.EventsEmit(ctx, "progress", 100)
	logMessage("File saved in " + outputFilePath, ctx)
	return true
}

// Generate share link
func generateShareLink(isExtLink bool, publicKey string) string {
	if isExtLink {
		return LINK_HAT_SH + publicKey
	} else {
		return LINK_APP + publicKey
	}
}

// Check private and public keys validity
func checkKeys(privateKeyBytes, publicKeyBytes []byte) bool {
	if len(privateKeyBytes) != crypto_kx_SECRETKEYBYTES {
		return false
	}

	if len(publicKeyBytes) != crypto_kx_PUBLICKEYBYTES {
		return false
	}

	if bytes.Equal(privateKeyBytes, publicKeyBytes) {
		return false
	}

	return true
}

func logMessage(message string, ctx context.Context) {
	runtime.EventsEmit(ctx, "log", message)
}