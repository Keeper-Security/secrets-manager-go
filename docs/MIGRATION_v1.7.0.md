# Migrating from v1.6.x to v1.7.0

This guide covers the two breaking changes in v1.7.0 and the steps to upgrade safely.

For the full list of changes, see [CHANGELOG.md](CHANGELOG.md).

---

## Requirements

- Go 1.16 or later (previously 1.14+)
- No new external dependencies; the SDK still uses only the Go standard library

---

## Breaking Change 1: Minimum Go version raised to 1.16

### Why

The `ioutil` package was deprecated in Go 1.16. All usages have been replaced with `io` and `os` equivalents. (KSM-616)

### Steps

**1. Verify your Go version:**

```bash
go version
# Must report go1.16 or later
```

**2. Update your `go.mod`:**

```go
// v1.6.x
go 1.14

// v1.7.0
go 1.16
```

**3. Update CI/CD base images.** Any image using `golang:1.15` or earlier will fail to build:

```yaml
# v1.6.x
go-version: "1.15.x"  # will fail to build the SDK

# v1.7.0
go-version: "1.16.x"  # minimum supported
```

---

## Breaking Change 2: Nil returns on decryption failure

### Why

Four exported functions previously returned non-nil empty stubs when decryption failed. For example, `NewRecordFromJson` would return a `*Record` with an empty `Uid` and no field data rather than `nil`. Callers had no reliable way to distinguish a successfully decrypted record from a silently failed one.

v1.7.0 returns `nil` at all decryption failure points. This is the correct behavior: a failed decryption produces no usable value. Code that calls these functions directly without a nil check will now panic on dereference instead of silently operating on empty data.

**Note**: Most applications call `GetSecrets` and never call these functions directly. If you only use `GetSecrets`, `GetSecretsByTitle`, or `Save`, skip to the [GetSecrets section](#getsecrets-just-bound-flow-ksm-916) below.

### Affected functions

| Function | Change |
|----------|--------|
| `NewRecordFromJson` (KSM-911) | Returns `nil` on record key or data decryption failure |
| `NewFolderFromJson` (KSM-913) | Returns `nil` on folder key or name decryption failure |
| `NewKeeperFolder` (KSM-913) | Returns `nil` on folder key or name decryption failure |
| `NewKeeperFileFromJson` (KSM-914) | Returns `nil` on file key decryption failure |

### How to audit your code

```bash
grep -rn "NewRecordFromJson\|NewFolderFromJson\|NewKeeperFolder\|NewKeeperFileFromJson" .
```

Any call site that dereferences the result without a nil check needs updating.

### Migration patterns

#### NewRecordFromJson

```go
// v1.6.x — decryption failure returned a stub with empty fields; no panic
record := NewRecordFromJson(data, key, folderUid)
fmt.Println(record.Title()) // printed "" silently on decryption failure

// v1.7.0 — decryption failure returns nil; panics without the check
record := NewRecordFromJson(data, key, folderUid)
if record == nil {
    // decryption failed; skip or return an error
    continue
}
fmt.Println(record.Title())
```

#### NewFolderFromJson / NewKeeperFolder

```go
// v1.6.x
folder := NewFolderFromJson(data, key)
fmt.Println(folder.Name) // printed "" silently on decryption failure

// v1.7.0
folder := NewFolderFromJson(data, key)
if folder == nil {
    continue
}
fmt.Println(folder.Name)
```

#### NewKeeperFileFromJson

```go
// v1.6.x
file := NewKeeperFileFromJson(data, key)
meta := file.GetMeta() // returned empty struct silently on decryption failure

// v1.7.0
file := NewKeeperFileFromJson(data, key)
if file == nil {
    continue
}
meta := file.GetMeta()
```

### GetSecrets just-bound flow (KSM-916)

This affects the first `GetSecrets` call after presenting a one-time token, when the server returns `encryptedAppKey`. Previously, if the app key could not be decrypted, `GetSecrets` returned an empty record slice with a `nil` error — indistinguishable from a legitimately empty vault. It now returns an error.

No code change is required if you already handle the error return from `GetSecrets`. The behavior change is that a previously silent failure is now surfaced:

```go
// v1.6.x — app key decryption failure returned ([], nil); silently appeared as empty vault
records, err := sm.GetSecrets([]string{})
if err != nil {
    log.Fatal(err)
}
if len(records) == 0 {
    // Could be empty vault OR silent decryption failure — no way to tell
}

// v1.7.0 — app key decryption failure returns (nil, error)
records, err := sm.GetSecrets([]string{})
if err != nil {
    log.Fatal(err) // now correctly surfaces the failure
}
```

---

## No other API changes

All other public functions, types, and interfaces are unchanged. The module path remains `github.com/keeper-security/secrets-manager-go/core`.

```bash
go get github.com/keeper-security/secrets-manager-go/core@v1.7.0
go mod tidy
```
