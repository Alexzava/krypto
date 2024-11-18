package main

import (
    "errors"

    "github.com/ebitengine/purego"
)


const (
    crypto_kx_PUBLICKEYBYTES = 32
    crypto_kx_SECRETKEYBYTES = 32
    crypto_kx_SESSIONKEYBYTES = 32
    SCALARMULT_CURVE25519_BYTES = 32
)

func crypto_kx_keypair() ([]byte, []byte) {
    publicKey := make([]byte, crypto_kx_PUBLICKEYBYTES)
    secretKey := make([]byte, crypto_kx_SECRETKEYBYTES)

    var crypto_kx_keypair_sodium func(pk []byte, sk []byte) int
    purego.RegisterLibFunc(&crypto_kx_keypair_sodium, sodium, "crypto_kx_keypair")

    crypto_kx_keypair_sodium(publicKey, secretKey)

    return publicKey, secretKey
}

func crypto_kx_client_session_keys(clientPublicKey []byte, clientSecretKey []byte, serverPublicKey []byte) ([]byte, []byte, error) {
    rx := make([]byte, crypto_kx_SESSIONKEYBYTES)
    tx := make([]byte, crypto_kx_SESSIONKEYBYTES)

    var crypto_kx_client_session_keys_sodium func(
        rx []byte,
        tx []byte,
        client_pk []byte,
        client_sk []byte,
        server_pk []byte,
    ) int
    purego.RegisterLibFunc(&crypto_kx_client_session_keys_sodium, sodium, "crypto_kx_client_session_keys")

    v := crypto_kx_client_session_keys_sodium(
        rx,
        tx,
        clientPublicKey,
        clientSecretKey,
        serverPublicKey,
    )

    if v != 0 {
        return nil, nil, errors.New("Suspicious server public key")
    }
    return rx, tx, nil
}

func crypto_kx_server_session_keys(serverPublicKey []byte, serverSecretKey []byte, clientPublicKey []byte) ([]byte, []byte, error) {
    rx := make([]byte, crypto_kx_SESSIONKEYBYTES)
    tx := make([]byte, crypto_kx_SESSIONKEYBYTES)

    var crypto_kx_server_session_keys_sodium func(
        rx []byte,
        tx []byte,
        server_pk []byte,
        server_sk []byte,
        client_pk []byte,
    ) int
    purego.RegisterLibFunc(&crypto_kx_server_session_keys_sodium, sodium, "crypto_kx_server_session_keys")

    v := crypto_kx_server_session_keys_sodium(
        rx,
        tx,
        serverPublicKey,
        serverSecretKey,
        clientPublicKey,
    )

    if v != 0 {
        return nil, nil, errors.New("Suspicious client public key")
    }
    return rx, tx, nil
}

func crypto_scalarmult_base(secretKey []byte) []byte {
    publicKey := make([]byte, SCALARMULT_CURVE25519_BYTES)

    var crypto_scalarmult_base_sodim func(q []byte, n []byte)
    purego.RegisterLibFunc(&crypto_scalarmult_base_sodim, sodium, "crypto_scalarmult_base")

    crypto_scalarmult_base_sodim(publicKey, secretKey)

    return publicKey
}