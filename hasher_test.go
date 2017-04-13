package hdkeys // import "go.rls.moe/hdkeys"

import (
	"crypto/rand"
	"errors"
	"github.com/stretchr/testify/require"
	"hash"
	"testing"
)

func Benchmark_stretchpw(b *testing.B) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		b.Fatal(err)
		b.Fail()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pw := make([]byte, 12)
		_, err = rand.Read(pw)
		if err != nil {
			b.Fatal(err)
			b.Fail()
		}
		_, err = stretchpw(string(pw), salt, 64)
		if err != nil {
			b.Fatal(err)
			b.Fail()
		}
	}
}

func Test_stretchpw(t *testing.T) {
	a := require.New(t)
	b, err := stretchpw("", []byte{}, 0)
	a.Nil(b)
	a.Error(err)
	a.EqualValues(err.Error(), "Short key")

	b, err = stretchpw("", []byte{}, 8)
	a.EqualValues([]byte{0x9d, 0x8b, 0x1f, 0x8e, 0xf6, 0xcb, 0x80, 0x4a}, b)
	a.NoError(err)

	b, err = stretchpw("", []byte{}, 1025)
	a.Nil(b)
	a.Error(err)
	a.EqualValues(err.Error(), "Key overstretch")
}

func Test_stretchint(t *testing.T) {
	a := require.New(t)

	orghasher := hasher

	hasher = func([]byte) (hash.Hash, error) {
		return nil, errors.New("Error")
	}

	_, err := stretchint([]byte{})
	a.Error(err)
	a.EqualValues(err.Error(), "Error")

	hasher = orghasher

	b, err := stretchint(nil)
	a.NoError(err)
	a.EqualValues([]byte{0x78, 0x6a, 0x2, 0xf7, 0x42, 0x1, 0x59, 0x3, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55, 0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce}, b)
}
