package hdkeys

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// SerializeKey returns a base64 representation of the current key
func (h *HDKey) SerializeKey() (string, error) {
	if len(h.int) != hasherSize {
		return "", errors.New("Key is not properly derived")
	}
	var out = make([]byte, len(h.int))
	copy(out, h.int)
	var outDepth = make([]byte, 8)
	binary.LittleEndian.PutUint64(outDepth, uint64(h.depth))
	var outFinal byte = 0
	if h.isFinal {
		outFinal = 1
	}
	out = append(out, append(outDepth, outFinal)...)
	return base64.RawStdEncoding.EncodeToString(out), nil
}

// UnserializeKey reads the incoming raw serialization of a key and modifies the current key to match
// the specification of that string
// The string must be base64 encoded.
func (h *HDKey) UnserializeKey(raw string) error {
	dat, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	if len(dat) != hasherSize+8+1 {
		return errors.New("Input data is not a serialized key")
	}
	h.int = dat[:hasherSize]
	h.depth = int(binary.LittleEndian.Uint64(dat[hasherSize : hasherSize+8]))
	if dat[hasherSize+8 : hasherSize+8+1][0] == 1 {
		h.isFinal = true
	}
	return nil
}
