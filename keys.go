package hdkeys // import "go.rls.moe/hdkeys"

import (
	"errors"
	"strings"
)

// HDKey is a hierarchival, deterministic key
// It can be used when your application requires to create
// several seperate keys that need to be recreatable with minimal
// knowledge and a root secret while maintaining security somewhat
type HDKey struct {
	int     []byte
	isFinal bool
	depth   int
}

// NewHDKey creates an empty root key
// To derive actual keys, use the functions provided by the root key.
// A root key is not safe, you have to put secrets into it to get
// a secure key out of it.
func NewHDKey() *HDKey {
	return &HDKey{int: []byte{}, depth: 0}
}

// padkey will stretch the internal key if it's shorter than the hash
// length and also check if the key is final
func (h *HDKey) padkey() error {
	if h.depth == 0 {
		// Key is empty so it's a root key, abort any operations
		// This means root keys will ignore finalization
		return nil
	}
	if h.isFinal {
		return errors.New("Key is finalized")
	}
	if len(h.int) != hasherSize {
		var err error
		h.int, err = stretchint(h.int)
		return err
	}
	return nil
}

// DerivePath will accept a slash seperated path of strings
// which it will recursively apply to the root keys.
// THe resulting key is returned.
func (h *HDKey) DerivePath(path string) (*HDKey, error) {
	err := h.padkey()
	if err != nil {
		return nil, err
	}

	if len(path) == 0 {
		return h, nil
	}
	pathSegments := strings.Split(path, "/")

	{
		// Trim empty path segments
		newPathSegments := []string{}
		for k := range pathSegments {
			trimmed := strings.TrimSpace(pathSegments[k])
			if len(trimmed) > 0 {
				newPathSegments = append(newPathSegments, trimmed)
			}
		}
		pathSegments = newPathSegments
	}

	if len(pathSegments) == 1 {
		seg := pathSegments[0]
		newInt, err := stretchpw(seg, h.int, hasherSize)
		if err != nil {
			return nil, err
		}
		return &HDKey{int: newInt, depth: h.depth + 1}, nil
	} else if len(pathSegments) > 1 {
		next, err := h.DerivePath(pathSegments[0])
		if err != nil {
			return nil, err
		}
		return next.DerivePath(strings.Join(pathSegments[1:], "/"))
	}
	return nil, errors.New("Path is invalid")
}

// DerivePassword is used to generate a new HDKey from a password
// The node is not finalized using this method
// Unlike DerivePath, this method does not split the input at slashes
// Use it only for deriving a single child through user password input
// or similar password-like inputs, not actual derivation paths.
func (h *HDKey) DerivePassword(pass string) (*HDKey, error) {
	err := h.padkey()
	if err != nil {
		return nil, err
	}

	newInt, err := stretchpw(pass, h.int, hasherSize)
	if err != nil {
		return nil, err
	}
	return &HDKey{int: newInt, depth: h.depth + 1}, nil
}

// Finalize will prevent the key from being derived further
// It is recommended to do this on all leaf keys to prevent accidents
// The function will hash the internal state with one last round, modifying
// the node itself. A Finalized node and a non-Finalized node will have differing states
//
// The root node will ignore the finalization
func (h *HDKey) Finalize() error {
	err := h.padkey()
	if err != nil {
		return err
	}

	hash, err := hasher([]byte{})
	if err != nil {
		return err
	}
	hash.Write(h.int)
	h.int = hash.Sum([]byte{})
	h.isFinal = true
	return nil
}

// GetBytes returns the raw byte slice of the key in form of a copy
// This will not work on non-finalized nodes
func (h *HDKey) GetBytes() ([]byte, error) {
	if !h.isFinal {
		return nil, errors.New("Key not final")
	}
	out := make([]byte, len(h.int))
	copy(out, h.int)
	return out, nil
}

// IsFinal indicates if the key is finalized and can read out it's secret
func (h *HDKey) IsFinal() bool {
	return h.isFinal
}

// FinalizedCopy returns a copy of the underlying key node that is marked
// as finalized. This may be useful if you need to get bytes of a intermediate node
func (h *HDKey) FinalizedCopy() *HDKey {
	out := make([]byte, len(h.int))
	copy(out, h.int)
	return &HDKey{int: out, isFinal: true, depth: h.depth}
}

// Depth returns the number of hierarchical levels above the current key
//
// Due to the nature of how keys are generated, a lower number indicates
// better/more secure keys (as they aren't as stretched thin yet) and higher
// number indicate the entropy of the initial node is thin stretched
func (h *HDKey) Depth() int {
	return h.depth
}
