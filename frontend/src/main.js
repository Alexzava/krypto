import './bootstrap.min.css'
import './bootstrap.bundle.min.js'
import './popper.min.js'
import './style.css'
import {
    ShowFilePickerDialog, 
    GenerateKeyPair,
    ExportPrivateKey,
    ImportPrivateKey,
    GenerateShareLink,
    GenerateShareQRCode,
    GenerateRandomPassword,
    EncryptSymmetric,
    DecryptSymmetric,
    EncryptAsymmetric,
    DecryptAsymmetric,
    OpenRepository
} from '../wailsjs/go/main/App'

import {
    OnFileDrop,
    ClipboardSetText
} from '../wailsjs/runtime/runtime'

import copyIcon from './assets/icons/copy.svg'
import closedEyeIcon from './assets/icons/eye-closed.svg'
import openEyeIcon from './assets/icons/eye-open.svg'
import checkIcon from './assets/icons/check.svg'

var selectedFile
var isPasswordMode = true

window.runtime.EventsOn("progress", (progress) => {
    if(progressBar) {
        progressBar.style.width = progress + "%"
        progressBar.textContent = progress + "%"
    }
})

window.runtime.EventsOn("log", (message) => {
    let currentDate = new Date()
    console.log("["+ currentDate + "] - " + message + "\n")

    if(logsTextArea) {
        logsTextArea.value += "["+ currentDate + "] - " + message + "\n\n"
    }
})

OnFileDrop((x, y, paths) => {}, null)

window.runtime.EventsOn("filedrop", (message) => {
    selectedFile = message
    toggleFilePickerView()
})

window.onload = () => {
    if(passwordModeSelector && publicKeyModeSelector) {
        passwordModeSelector.onclick = () => { switchToPasswordMode() }
        publicKeyModeSelector.onclick = () => { switchToPublicKeyMode() }
    }

    if(passwordVisibilityButton) {
        passwordVisibilityButton.onclick = () => { togglePasswordVisibility() }
    }

    if(encryptActionButton && decryptActionButton) {
        encryptActionButton.onclick = () => { 
            if(isPasswordMode) {
                window.EncryptSymmetric()
            } else {
                window.EncryptAsymmetric()
            }
        }

        decryptActionButton.onclick = () => { 
            if(isPasswordMode) {
                window.DecryptSymmetric()
            } else {
                window.DecryptAsymmetric()
            }
        }
    }

    if(removeSelectedFileButton) {
        removeSelectedFileButton.onclick = () => { 
            selectedFile = ""

            if(passwordInput && personalPrivateKeyInput && recipientPublicKeyInput && progressBar) {
                passwordInput.value = ""
                personalPrivateKeyInput.value = ""
                recipientPublicKeyInput.value = ""
                progressBar.style.width = "0%"
                progressBar.textContent = "0%"
                switchToPasswordMode()
            }
            toggleFilePickerView() 
        }
    }

    if(switchHatshShareLink) {
        switchHatshShareLink.addEventListener('change', () => {
            window.GenerateShareQRCode()
            window.GenerateShareLink()
        })
    }

    if(generateKeyPairModal) {
        generateKeyPairModal.addEventListener('hidden.bs.modal', event => {
            if(copyShareLinkButtonIcon && 
                copyShareLinkButtonText && 
                generateKeyPairPublicKeyText &&
                generateKeyPairPrivateKeyText) {

                copyShareLinkButtonIcon.src = copyIcon
                copyShareLinkButtonText.textContent = "Copy"

                generateKeyPairPublicKeyText.value = ""
                generateKeyPairPrivateKeyText.value = ""
            }
        })
    }
}

function switchToPasswordMode() {
    isPasswordMode = true
    if(passwordModeContainer && publicKeyModeContainer) {
        passwordModeContainer.classList.remove("d-none")
        passwordModeContainer.classList.add("d-block")

        publicKeyModeContainer.classList.remove("d-block")
        publicKeyModeContainer.classList.add("d-none")
    }
}

function switchToPublicKeyMode() {
    isPasswordMode = false
    if(passwordModeContainer && publicKeyModeContainer) {
        passwordModeContainer.classList.add("d-none")
        passwordModeContainer.classList.remove("d-block")

        publicKeyModeContainer.classList.add("d-block")
        publicKeyModeContainer.classList.remove("d-none")
    }
}

function togglePasswordVisibility() {
    if(passwordInput) {
        if(passwordInput.type === "password") {
            passwordInput.type = "text"
            if(showPasswordIcon) {
                showPasswordIcon.src = closedEyeIcon
            }
        } else {
            passwordInput.type = "password"
             if(showPasswordIcon) {
                showPasswordIcon.src = openEyeIcon
            }
        }
    }
}

function toggleFilePickerView() {
    if(introView && 
        filePickerSelector && 
        filePickerList && 
        selectedFileName && 
        filePickerView &&
        passwordView &&
        actionButtonsView) {

        introView.classList.toggle("d-none")
        filePickerSelector.classList.toggle("d-none")

        filePickerList.classList.toggle("d-none")
        selectedFileName.textContent = selectedFile.replace(/^.*[\\/]/, '')

        passwordView.classList.toggle("d-none")

        actionButtonsView.classList.toggle("d-none")
    }
}

window.CopyShareLink = () => {
    if(publicKeyQRCodeImage && 
        publicKeyQRCodeImage.getAttribute("data-attr") &&
        publicKeyQRCodeImage.getAttribute("data-attr").length > 0) {

        ClipboardSetText(publicKeyQRCodeImage.getAttribute("data-attr"))
            .then((result) => {
                if(result) {
                    if(copyShareLinkButtonIcon && copyShareLinkButtonText) {
                        copyShareLinkButtonIcon.src = checkIcon
                        copyShareLinkButtonText.textContent = "Copied"
                    }
                }
            })
    }
}

function showErrorModal(message) {
    if(errorModal && errorModalContent) {
        errorModalContent.textContent = message
        let modalErrorEl = new bootstrap.Modal('#errorModal', {})
        modalErrorEl.show()
    }
}


// Go App Func
window.ShowFilePickerDialog = () => {
    try {
        ShowFilePickerDialog()
            .then((result) => {
                if(result != "") {
                    selectedFile = result
                    toggleFilePickerView()
                }
            })
            .catch((err) => {
                console.error(err)
            })
    } catch (err) {
        console.error(err)
    }
}

window.GenerateRandomPassword = () => {
    try {
        GenerateRandomPassword()
            .then((result) => {
                if(passwordInput) {
                    passwordInput.value = result
                }
            })
            .catch((err) => {
                console.error(err)
            })
    } catch (err) {
        console.error(err)
    }
}

window.GenerateKeyPair = () => {
    try {
        GenerateKeyPair()
            .then((result) => {
                generateKeyPairPublicKeyText.value = result[0]
                generateKeyPairPrivateKeyText.value = result[1]
                window.GenerateShareQRCode()
                window.GenerateShareLink()
            })
            .catch((err) => {
                console.error(err)
            })
    } catch (err) {
        console.error(err)
    }
}

window.GenerateShareLink = () => {
    let isExtLink = false
    if(switchHatshShareLink && switchHatshShareLink.checked) {
        isExtLink = true
    }

    try {
        if(generateKeyPairPublicKeyText) {
            GenerateShareLink(isExtLink, generateKeyPairPublicKeyText.value)
            .then((result) => {
                if(result != "" && publicKeyQRCodeImage) {
                    publicKeyQRCodeImage.setAttribute("data-attr", result)
                }
            })
            .catch((err) => {
                console.error(err)
            })
        }
        
    } catch(err) {
        console.error(err)
    }
}

window.GenerateShareQRCode = () => {
    let isExtLink = false
    if(switchHatshShareLink && switchHatshShareLink.checked) {
        isExtLink = true
    }

    try {
        if(generateKeyPairPublicKeyText) {
            GenerateShareQRCode(isExtLink, generateKeyPairPublicKeyText.value)
            .then((result) => {
                if(result != "" && publicKeyQRCodeImage) {
                    publicKeyQRCodeImage.src = "data:image/png;base64," + result
                }
            })
            .catch((err) => {
                console.error(err)
            })
        }
        
    } catch(err) {
        console.error(err)
    }
}

window.ExportPrivateKey = () => {
    try {
        if(generateKeyPairPrivateKeyText) {
            ExportPrivateKey(generateKeyPairPrivateKeyText.value)
        }
    } catch (err) {
        console.error(err)
    }
}

window.ImportPrivateKey = () => {
    try {
        ImportPrivateKey()
        .then((result) => {
            if(result != "" && personalPrivateKeyInput) {
                personalPrivateKeyInput.value = result
            }
        })
        .catch((err) => {
            console.error(err)
        })
    } catch (err) {
        console.error(err)
    }
}

window.EncryptSymmetric = () => {
    try {
        if(passwordInput && passwordInput.value.length > 0) {
            EncryptSymmetric(passwordInput.value, selectedFile)
            .then((result) => {
                if(!result) {
                    showErrorModal("There was an error during the encryption process. Please read the logs for more details.")
                }

                if(encryptActionButton && decryptActionButton) {
                    encryptActionButton.disabled = false
                    decryptActionButton.disabled = false
                }
            })

            if(encryptActionButton && decryptActionButton) {
                encryptActionButton.disabled = true
                decryptActionButton.disabled = true
            }
        }
    } catch (err) {
        console.error(err)
    }
}

window.DecryptSymmetric = () => {
    try {
        if(passwordInput && passwordInput.value.length > 0) {
            DecryptSymmetric(passwordInput.value, selectedFile)
            .then((result) => {
                if(!result) {
                    showErrorModal("There was an error during the decryption process. Please read the logs for more details.")
                }

                if(encryptActionButton && decryptActionButton) {
                    encryptActionButton.disabled = false
                    decryptActionButton.disabled = false
                }
            })
            if(encryptActionButton && decryptActionButton) {
                encryptActionButton.disabled = true
                decryptActionButton.disabled = true
            }
        }
    } catch (err) {
        console.error(err)
    }
}

window.EncryptAsymmetric = () => {
    try {
        if(personalPrivateKeyInput && 
            personalPrivateKeyInput.value.length > 0 &&
            recipientPublicKeyInput &&
            recipientPublicKeyInput.value.length > 0) {
            EncryptAsymmetric(personalPrivateKeyInput.value, recipientPublicKeyInput.value, selectedFile)
            .then((result) => {
                if(!result) {
                    showErrorModal("There was an error during the encryption process. Please read the logs for more details.")
                }

                if(encryptActionButton && decryptActionButton) {
                    encryptActionButton.disabled = false
                    decryptActionButton.disabled = false
                }
            })
            if(encryptActionButton && decryptActionButton) {
                encryptActionButton.disabled = true
                decryptActionButton.disabled = true
            }
        }
    } catch (err) {
        console.error(err)
    }
}

window.DecryptAsymmetric = () => {
    try {
        if(personalPrivateKeyInput && 
            personalPrivateKeyInput.value.length > 0 &&
            recipientPublicKeyInput &&
            recipientPublicKeyInput.value.length > 0) {
            DecryptAsymmetric(personalPrivateKeyInput.value, recipientPublicKeyInput.value, selectedFile)
            .then((result) => {
                if(!result) {
                    showErrorModal("There was an error during the decryption process. Please read the logs for more details.")
                }

                if(encryptActionButton && decryptActionButton) {
                    encryptActionButton.disabled = false
                    decryptActionButton.disabled = false
                }
            })
            if(encryptActionButton && decryptActionButton) {
                encryptActionButton.disabled = true
                decryptActionButton.disabled = true
            }
        }
    } catch (err) {
        console.error(err)
    }
}

window.OpenRepository = () => {
    try {
        OpenRepository()
    } catch (err) {
        console.error(err)
    }
}