// Package hdkeys provides Hierarchical, Deterministic Keys (HDKeys)
//
// HDKeys allow effective management of multiple secrets using only one root secret as a source.
//
// Keys can be derived via path, which increases their depth, via a password which produces a key at the same
// depth or via finalization which allows to retrieve the final secret from the key.
//
// The library can be useful when a single user password must secure multiple resources independently
// or when a server owner wants to encrypt all data with their own secret plus user password for additional security.
//
// Paths in this library are seperated by a forward slash which is ignored for processing paths.
//
// Passwords are not preprocessed and directly fed into a PBKDF2 function using SHA3-512 at 50000 iterations
package hdkeys
