package hdkeys // import "go.rls.moe/hdkeys"

import (
	"errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"hash"
)

var hasher func(key []byte) (hash.Hash, error)
var hasherSize int
var passhash func() hash.Hash

func init() {
	hasher = blake2b.New512
	hasherSize = blake2b.Size
	passhash = sha3.New512
}

// Use this to set the number of iterations on password derivation
// Useful for when you don't have a powerful machine or use gopherjs
var PasswordIterations = 150000

// stretchpw takes about half a second on a modern CPU (Ryzen 7 1700X)
func stretchpw(pw string, salt []byte, length int) ([]byte, error) {
	if length < 8 {
		return nil, errors.New("Short key")
	} else if length > 1024 {
		return nil, errors.New("Key overstretch")
	}
	return pbkdf2.Key([]byte(pw), salt, PasswordIterations, length, passhash), nil
}

// Stretch int will put the incoming value through a single iteration of the hasher algorithm
// this only fits it into the same size as every other key internally.
func stretchint(int []byte) ([]byte, error) {
	hash, err := hasher([]byte{})
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(int)
	if err != nil {
		return nil, err
	}
	return hash.Sum([]byte{}), err
}
