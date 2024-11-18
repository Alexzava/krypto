package main

import (
    "unsafe"
    "errors"

    "github.com/ebitengine/purego"
)


const (
    crypto_stream_chacha20_ietf_KEYBYTES = 32
    crypto_stream_chacha20_ietf_NONCEBYTES = 12
    crypto_stream_chacha20_ietf_ABYTES = 16

    crypto_secretstream_xchacha20poly1305_ABYTES = crypto_stream_chacha20_ietf_ABYTES + 1
    crypto_secretstream_xchacha20poly1305_KEYBYTES = crypto_stream_chacha20_ietf_KEYBYTES
    crypto_secretstream_xchacha20poly1305_HEADERBYTES = 24

    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = byte(0)
    crypto_secretstream_xchacha20poly1305_TAG_FINAL = byte(3)
)

type Crypto_secretstream_xchacha20poly1305_state struct {
    k [crypto_stream_chacha20_ietf_KEYBYTES]byte
    nonce [crypto_stream_chacha20_ietf_NONCEBYTES]byte
    _pad [8]byte
}

func crypto_secretstream_xchacha20poly1305_init_push(key []byte) (Crypto_secretstream_xchacha20poly1305_state, []byte) {
	var state Crypto_secretstream_xchacha20poly1305_state
    header := make([]byte, crypto_secretstream_xchacha20poly1305_HEADERBYTES)

    var crypto_secretstream_xchacha20poly1305_init_push_sodium func(
        state uintptr,
        header []byte,
        k []byte,
    ) int
    purego.RegisterLibFunc(&crypto_secretstream_xchacha20poly1305_init_push_sodium, sodium, "crypto_secretstream_xchacha20poly1305_init_push")

    crypto_secretstream_xchacha20poly1305_init_push_sodium(
        uintptr(unsafe.Pointer(&state)),
        header,
        key,
    )

    return state, header
}

func crypto_secretstream_xchacha20poly1305_push(state Crypto_secretstream_xchacha20poly1305_state, message []byte, tag byte) []byte {
    cipherText := make([]byte, len(message) + crypto_secretstream_xchacha20poly1305_ABYTES)

    var crypto_secretstream_xchacha20poly1305_push_sodium func(
        state uintptr,
        c []byte, 
        clen_p int,
        m []byte, 
        mlen int,
        ad []byte, 
        adlen int, 
        tag byte,
    ) int
    purego.RegisterLibFunc(
        &crypto_secretstream_xchacha20poly1305_push_sodium, 
        sodium, 
        "crypto_secretstream_xchacha20poly1305_push",
    )

    crypto_secretstream_xchacha20poly1305_push_sodium(
        uintptr(unsafe.Pointer(&state)),
        cipherText,
        0, // nil
        message,
        len(message),
        nil,
        0,
        tag,
    )

    return cipherText
}

func crypto_secretstream_xchacha20poly1305_init_pull(header []byte, key []byte) (Crypto_secretstream_xchacha20poly1305_state, error) {
    var state Crypto_secretstream_xchacha20poly1305_state

    var crypto_secretstream_xchacha20poly1305_init_pull_sodium func(
        state uintptr,
        header []byte,
        k []byte,
    ) int
    purego.RegisterLibFunc(
        &crypto_secretstream_xchacha20poly1305_init_pull_sodium, 
        sodium, 
        "crypto_secretstream_xchacha20poly1305_init_pull",
    )

    v := crypto_secretstream_xchacha20poly1305_init_pull_sodium(
        uintptr(unsafe.Pointer(&state)),
        header,
        key,
    )

    if v != 0 {
        return state, errors.New("Invalid header")
    }
    
    return state, nil
}

func crypto_secretstream_xchacha20poly1305_pull(state Crypto_secretstream_xchacha20poly1305_state, cipherText []byte, tag []byte) ([]byte, error) {
    message := make([]byte, len(cipherText) - crypto_secretstream_xchacha20poly1305_ABYTES)

    //tag := []byte{ crypto_secretstream_xchacha20poly1305_TAG_MESSAGE }

    var crypto_secretstream_xchacha20poly1305_pull_sodium func(
        state uintptr,
        m []byte,
        mlen_p int,
        tag_p []byte,
        c []byte,
        clen int,
        ad []byte,
        adlen int,
    ) int
    purego.RegisterLibFunc(
        &crypto_secretstream_xchacha20poly1305_pull_sodium, 
        sodium, 
        "crypto_secretstream_xchacha20poly1305_pull",
    )

    v := crypto_secretstream_xchacha20poly1305_pull_sodium(
        uintptr(unsafe.Pointer(&state)),
        message,
        0, //nil
        tag,
        cipherText,
        len(cipherText),
        nil,
        0,
    )

    if v != 0 {
        return nil, errors.New("Invalid/incomplete/corrupted ciphertext")
    }
        
    return message, nil
}