package hdkeys

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	testingKeySerialization      = "vnF1ChYmOqO4R55gYuU98qDMD51p83DXP8XP1VHjI/wYPoUUEbDMeNVW+vNUQ9PLKyNCKdrjYFdy0lfgLy3LZgEAAAAAAAAAAA"
	testingFinalKeySerialization = "vnF1ChYmOqO4R55gYuU98qDMD51p83DXP8XP1VHjI/wYPoUUEbDMeNVW+vNUQ9PLKyNCKdrjYFdy0lfgLy3LZgEAAAAAAAAAAQ"
)

func TestHDKey_SerializeKey(t *testing.T) {
	a := require.New(t)

	key := NewHDKey()

	key, err := key.DerivePassword("hello from the crypto side")
	a.NoError(err)

	raw, err := key.SerializeKey()
	a.NoError(err)
	a.EqualValues(testingKeySerialization, raw)

	key.isFinal = true

	raw, err = key.SerializeKey()
	a.NoError(err)
	a.EqualValues(testingFinalKeySerialization, raw)

	key.int = []byte("Hello")

	_, err = key.SerializeKey()
	a.Error(err)
	a.EqualValues("Key is not properly derived", err.Error())
}

func TestHDKey_UnserializeKey(t *testing.T) {
	a := require.New(t)

	orgkey, err := NewHDKey().DerivePassword("hello from the crypto side")
	a.NoError(err)

	key := NewHDKey()

	err = key.UnserializeKey(testingKeySerialization)

	a.NoError(err)
	a.EqualValues(orgkey, key)

	err = key.UnserializeKey(testingFinalKeySerialization)

	orgkey.isFinal = true

	a.NoError(err)
	a.EqualValues(orgkey, key)

	err = key.UnserializeKey("AAAA")
	a.Error(err)
	a.EqualValues("Input data is not a serialized key", err.Error())

	err = key.UnserializeKey("....")
	a.Error(err)
	a.EqualValues("illegal base64 data at input byte 0", err.Error())
}
