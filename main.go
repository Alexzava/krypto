package main

import (
	"fmt"
	"flag"
	"log"
	"bytes"
	"syscall"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/sqweek/dialog"

	"golang.org/x/term"
)

var uiWindow fyne.Window
var progress float64
var progressLog string

func main() {
	var opMode int
	var inputFile string

	cli := flag.Bool("cli", false, "CLI mode")
	encrypt := flag.String("e", "", "Encrypt file. -e <filename>")
	decrypt := flag.String("d", "", "Decrypt file. -d <filename>")
	removeFile := flag.Bool("del", false, "Remove source file when done")
	flag.Parse()

	if len(*encrypt) > 0 && len(*decrypt) > 0 {
		panic("Please select only one operation mode. Encrypt (-e) or Decrypt (-d)")
	}

	if len(*encrypt) > 0 {
		opMode = MODE_ENCRYPT
		inputFile = *encrypt
	} else {
		opMode = MODE_DECRYPT
		inputFile = *decrypt
	}

	if *cli {
		// Ask for password
		fmt.Println("Enter a secure password\nPassword:")
		pass, _ := term.ReadPassword(int(syscall.Stdin))

		fmt.Println("Retype Password:")
		pass2, _ := term.ReadPassword(int(syscall.Stdin))

		if(bytes.Compare(pass, pass2) != 0 || len(pass) == 0) {
			panic("Passwords are invalid or does not match")
		}

		if opMode == MODE_ENCRYPT {
			Encrypt(inputFile, pass)
			if *removeFile {
				SecureDelete(inputFile)
			}
		} else {
			Decrypt(inputFile, pass)
			if *removeFile {
				SecureDelete(inputFile)
			}
		}
	} else {
		showUIWindow(inputFile)
	}
}

func showUIWindow(inputFile string) {
	a := app.New()
	uiWindow = a.NewWindow("KRYPTO")

	entryFileName := widget.NewEntry()
	entryFileName.SetPlaceHolder("Input file")
	if len(inputFile) > 0 {
		entryFileName.SetText(inputFile)
	}

	buttonSelectFile := widget.NewButton("Open", func() {
		file, err := dialog.File().Load()
		if err != nil {
			panic(err)
		}
		entryFileName.SetText(file)
	})

	entryPassword := widget.NewPasswordEntry()
	entryPassword.SetPlaceHolder("Password")

	checkSecureDelete := widget.NewCheck("Remove source file when done", func(value bool) {})
	configRow := container.NewGridWithRows(1,
		checkSecureDelete,
	)

	progressBar := widget.NewProgressBar()
	progressBar.Min = 0
	progressBar.Max = 100

	labelProgress := widget.NewLabel("...")

	progressRow := container.NewGridWithRows(2,
		progressBar,
		labelProgress,
	)

	buttonEncrypt := widget.NewButton("ENCRYPT", func() {
		Encrypt(entryFileName.Text, []byte(entryPassword.Text))
		if(checkSecureDelete.Checked) {
			SecureDelete(entryFileName.Text)
		}
	})

	buttonDecrypt := widget.NewButton("DECRYPT", func() {
		Decrypt(entryFileName.Text, []byte(entryPassword.Text))
		if(checkSecureDelete.Checked) {
			SecureDelete(entryFileName.Text)
		}
	})

	buttonsRow := container.NewGridWithColumns(3, 
		buttonEncrypt,
		layout.NewSpacer(),
		buttonDecrypt,
	)

	repoUrl, _ := url.Parse(REPO_URL)

	uiWindow.SetContent(container.NewVBox(
		widget.NewLabel("Select File"),
		entryFileName,
		buttonSelectFile,
		widget.NewLabel("Select Password"),
		entryPassword,
		configRow,
		buttonsRow,
		progressRow,
		container.NewGridWithColumns(3,
			widget.NewLabel("Made by alexzava"),
			layout.NewSpacer(),
			widget.NewHyperlink("Check for update", repoUrl),
		),
	))
	uiWindow.Resize(fyne.NewSize(500,400))

	go updateUILoop(progressBar, labelProgress)

	// Show window
	uiWindow.ShowAndRun()
}

func updateUILoop(progressBar *widget.ProgressBar, statusLabel *widget.Label) {
	prog := progress
	log := progressLog
	for {
		if prog != progress {
			prog = progress
			progressBar.SetValue(prog)
		}

		if log != progressLog {
			log = progressLog
			statusLabel.SetText(log)
		}
	}
}

func Encrypt(inputName string, password []byte) {
	header := CreateFileHeader()
	masterKey := DeriveKeyFromPassword(password, ARGON2_KEY_LEN, header.KeySalt)
	err := ProcessFile(MODE_ENCRYPT, inputName, "", header, masterKey, &progress, &progressLog)
	if err != nil {
		dialog.Message(err.Error()).Title("Error").Error()
		log.Fatal(err)
	}
}

func Decrypt(inputName string, password []byte) {
	header := ReadFileHeader(inputName)
	masterKey := DeriveKeyFromPassword(password, ARGON2_KEY_LEN, header.KeySalt)
	err := ProcessFile(MODE_DECRYPT, inputName, "", header, masterKey, &progress, &progressLog)
	if err != nil {
		dialog.Message(err.Error()).Title("Error").Error()
		log.Fatal(err)
	}
}

func SecureDelete(filename string) {
	OverwriteFile(filename, &progress, &progressLog)
}