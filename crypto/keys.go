package crypto

import "fmt"

import "encoding/hex"
import "crypto/ecdsa"
import "crypto/sha256"

import "golang.org/x/crypto/ripemd160"

import ethCrypto "github.com/ethereum/go-ethereum/crypto"
import secp256k1 "github.com/ethereum/go-ethereum/crypto/secp256k1"
import "github.com/mr-tron/base58"

const Version byte = 0

func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
    return ethCrypto.GenerateKey()
}

func PrivateKeyFromHexString(privHex string) (*ecdsa.PrivateKey, error) {
    return ethCrypto.HexToECDSA(privHex)
}

func PublicKeyFromPriv(priv *ecdsa.PrivateKey) *ecdsa.PublicKey {
    pub := priv.Public().(*ecdsa.PublicKey)
    return pub
}

func CompressPubkey(pub *ecdsa.PublicKey) []byte {
    return secp256k1.CompressPubkey(pub.X, pub.Y)
}

func AddressFromPublicKey(pub *ecdsa.PublicKey) string {
    pubHash := publicKeyHash(pub)

    addr := make([]byte, 25, 25)
    addr[0] = Version

    copy(addr[1:21], pubHash[:])

    digest := sha256.Sum256(addr[:21])
    digest = sha256.Sum256(digest[:])

    checksum := digest[:4]
    copy(addr[21:], checksum)

    return base58.Encode(addr)
}

func publicKeyHash(pub *ecdsa.PublicKey) []byte {
    compressedPub := CompressPubkey(pub)

    sha256Digest := sha256.Sum256(compressedPub)

    ripemd160Hasher := ripemd160.New()
    ripemd160Hasher.Write(sha256Digest[:])
    return ripemd160Hasher.Sum(make([]byte, 0, 0))
}

func example() {
    priv, _ := PrivateKeyFromHexString("d5c654eeff2cf1c6af16d721f31854ef447dfc61a6344bf1ba7108ec77d29b80")
    pub := PublicKeyFromPriv(priv)
    pubBytes := CompressPubkey(pub)

    fmt.Println(hex.EncodeToString(pubBytes))

    addr := AddressFromPublicKey(pub)
    fmt.Println(addr)
}

