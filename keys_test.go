package hdkeys // import "go.rls.moe/hdkeys"

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	emptykey         = &HDKey{int: []byte{}, depth: 0, isFinal: false}
	emptykeypad      = []uint8{0x78, 0x6a, 0x2, 0xf7, 0x42, 0x1, 0x59, 0x3, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55, 0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce}
	dkey_derived_key = &HDKey{int: []uint8{0x6, 0x34, 0x40, 0x11, 0x63, 0x9a, 0xdc, 0xa7, 0xb0, 0xe8, 0xdb, 0x88, 0x86, 0xd6, 0x62, 0xec, 0xd8, 0xd8, 0x39, 0x24, 0x22, 0xea, 0xfb, 0xf3, 0x42, 0x6f, 0x73, 0x58, 0xda, 0x74, 0xd9, 0x3b, 0xd6, 0xc, 0x39, 0xf0, 0x4f, 0x54, 0x72, 0x1e, 0x30, 0x13, 0x42, 0xae, 0x76, 0x8c, 0x73, 0x7b, 0x5b, 0x37, 0xbd, 0x4f, 0x6e, 0x38, 0x87, 0xfd, 0x59, 0xeb, 0xc6, 0x5b, 0x43, 0x67, 0xac, 0x5a}, isFinal: false, depth: 1}
	pwkey            = &HDKey{int: []uint8{0xbe, 0x71, 0x75, 0xa, 0x16, 0x26, 0x3a, 0xa3, 0xb8, 0x47, 0x9e, 0x60, 0x62, 0xe5, 0x3d, 0xf2, 0xa0, 0xcc, 0xf, 0x9d, 0x69, 0xf3, 0x70, 0xd7, 0x3f, 0xc5, 0xcf, 0xd5, 0x51, 0xe3, 0x23, 0xfc, 0x18, 0x3e, 0x85, 0x14, 0x11, 0xb0, 0xcc, 0x78, 0xd5, 0x56, 0xfa, 0xf3, 0x54, 0x43, 0xd3, 0xcb, 0x2b, 0x23, 0x42, 0x29, 0xda, 0xe3, 0x60, 0x57, 0x72, 0xd2, 0x57, 0xe0, 0x2f, 0x2d, 0xcb, 0x66}, isFinal: false, depth: 1}
	emptypwkey       = &HDKey{int: []uint8{0x9d, 0x8b, 0x1f, 0x8e, 0xf6, 0xcb, 0x80, 0x4a, 0x3d, 0xfd, 0x20, 0x2b, 0x1c, 0x13, 0x73, 0xd8, 0xa7, 0x6a, 0x72, 0x0, 0x3a, 0x28, 0x5a, 0x88, 0x20, 0xe3, 0x41, 0xd3, 0xad, 0x54, 0x65, 0x64, 0x7a, 0xe0, 0xd, 0xc, 0x8c, 0x9, 0x72, 0xf7, 0x3d, 0x99, 0x40, 0x19, 0xde, 0x29, 0xf, 0x95, 0xc8, 0x42, 0x8b, 0xa1, 0x0, 0x45, 0xb9, 0x2f, 0x4e, 0x20, 0xda, 0x51, 0xf0, 0x97, 0x31, 0xb9}, isFinal: false, depth: 1}
	finalkey         = &HDKey{int: []uint8{0xfc, 0x7e, 0xa, 0x48, 0x3b, 0x24, 0x59, 0xc4, 0x6b, 0x75, 0xbd, 0x85, 0x8e, 0x86, 0x52, 0x8b, 0x20, 0x4d, 0x4a, 0xc7, 0x9d, 0xbe, 0x2a, 0x71, 0xec, 0xe6, 0x98, 0xf5, 0x40, 0x98, 0xba, 0x1f, 0x2e, 0x59, 0x69, 0x4c, 0x17, 0xcb, 0xec, 0x72, 0x94, 0x6f, 0x15, 0xfc, 0xd4, 0x9b, 0x85, 0xd9, 0x20, 0xaf, 0x85, 0xb5, 0x0, 0x4e, 0x54, 0xd4, 0xec, 0x1d, 0x1b, 0x56, 0x81, 0x4d, 0x94, 0x2c}, isFinal: true, depth: 1}
)

func TestNewHDKey(t *testing.T) {
	a := require.New(t)

	a.NotNil(NewHDKey())

	key := NewHDKey()

	a.EqualValues(emptykey, key)

	a.NoError(key.padkey())

	// Check if padkey didn't manipulate the root node
	a.EqualValues(emptykey, key)
}

func TestHDKey_padkey(t *testing.T) {
	a := require.New(t)

	orgkey := &HDKey{int: []byte{}, depth: 1, isFinal: true}
	key := &HDKey{int: []byte{}, depth: 1, isFinal: true}

	key.padkey()

	a.EqualValues(orgkey, key)

	key.isFinal = false

	key.padkey()

	orgkey.int = emptykeypad
	orgkey.isFinal = false

	a.EqualValues(orgkey, key)

	a.NoError(key.padkey())
}

func TestHDKey_DerivePath(t *testing.T) {
	a := require.New(t)

	key := NewHDKey()

	key.isFinal = true
	key.depth = 1

	_, err := key.DerivePath("")

	a.Error(err)
	a.EqualValues(err.Error(), "Key is finalized")

	key.isFinal = false
	key.depth = 0

	dkey, err := key.DerivePath("")

	a.NoError(err)
	a.EqualValues(key, dkey)

	dkey, err = key.DerivePath("key")

	a.NoError(err)
	a.EqualValues(dkey_derived_key, dkey)

	dkey, err = key.DerivePath("key/path")

	a.NoError(err)

	dkey2, err := key.DerivePath("key")

	a.NoError(err)

	dkey2, err = dkey2.DerivePath("path")

	a.NoError(err)

	a.EqualValues(dkey, dkey2)

	_, err = key.DerivePath("/")

	a.Error(err)
	a.EqualValues(err.Error(), "Path is invalid")
}

func TestHDKey_DerivePassword(t *testing.T) {
	a := require.New(t)

	key := NewHDKey()

	key.isFinal = true
	key.depth = 1

	_, err := key.DerivePassword("")

	a.Error(err)
	a.EqualValues(err.Error(), "Key is finalized")

	key.isFinal = false
	key.depth = 0

	dkey, err := key.DerivePassword("")

	a.NoError(err)
	a.EqualValues(emptypwkey, dkey)

	dkey, err = key.DerivePassword("hello from the crypto side")

	a.NoError(err)
	a.EqualValues(pwkey, dkey)
}

func TestHDKey_Depth(t *testing.T) {
	a := require.New(t)

	key := HDKey{depth: 1}

	a.Equal(key.depth, key.Depth())
}

func TestHDKey_IsFinal(t *testing.T) {
	a := require.New(t)

	key, err := NewHDKey().DerivePassword("hello from the crypto side")
	a.NoError(err)
	a.False(key.IsFinal())
	a.NoError(key.Finalize())
	a.True(key.isFinal)
}

func TestHDKey_GetBytes(t *testing.T) {
	a := require.New(t)

	key := HDKey{int: []byte("Hello World")}

	dat, err := key.GetBytes()

	a.Error(err)
	a.EqualValues("Key not final", err.Error())

	key.isFinal = true

	dat, err = key.GetBytes()

	a.NoError(err)
	a.Equal([]byte("Hello World"), dat)
}

func TestHDKey_FinalizedCopy(t *testing.T) {
	a := require.New(t)

	key := &HDKey{int: []byte{22, 23}, isFinal: false, depth: 20}

	key2 := key.FinalizedCopy()

	a.True(&key.int != &key2.int)
	a.NotEqual(key, key2)
	key.isFinal = true
	a.Equal(key, key2)
	a.EqualValues(key, key2)
}

func TestHDKey_Finalize(t *testing.T) {
	a := require.New(t)

	key, err := NewHDKey().DerivePassword("hello from the crypto side")
	a.NoError(err)

	a.NoError(key.Finalize())

	a.Error(key.Finalize())

	a.EqualValues(finalkey, key)
}