# hdkeys

hdkeys is a library for managing a set of hierarchical and deterministic keys.

A key always has a parent node and can derive any number of child nodes from
either a path specification or a password/secret as long as it's not finalized.

Finalized keys allow the retrieval of the resulting secret.

## Install

```
go get go.rls.moe/hdkeys
```

The vendor folder is included so the library should already work without problems

## Usage

All keys are derived from the root key which is created with `NewHDKey()`

Example:

```go
key := NewHDKey()
```

The root key is a fixed constant so you should feed a secret into it to get a proper
secret root out of it.

```go
key, err := NewHDKey().DerivePassword("my secret is safe")
if err != nil {
    log.Fatal(err)
    return
}
```

Congrats, you derived from a secret.

If you want to use a key, the recommendation for this library is to first input
a path to make the key specific for the usage;

```go
key, err := rootkey.DerivePath("webserver/cookie/secret")
if err != nil {
    log.Fatal(err)
    return
}
```

You cannot currently retrieve the secret, you need to finalize a key for that;

```go
finalKey, err := key.Finalize()
if err != nil {
    log.Fatal(err)
    return
}
```

The new variable `finalKey` differs from key and can be read with `GetBytes()`

However, you **cannot** make any further derivations from a finalized key.

If you need to derive a finalized key, you can make a copy of the key and finalize it with
`FinalizedCopy()` which returns a Finalized Copy of the current key.

To check if a key is finalized you can use `IsFinal()`

## License

See `LICENSE`

## Todo

There isn't anything on my Todo list but if there is a bug or security flaw, please open
a pull request or contact me via email.

## Security Audit

This library is not audited and I make no guarantees about it's security (but it should be fairly safe)