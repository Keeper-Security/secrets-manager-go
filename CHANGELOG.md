# Changelog

## v1.7.0

### Upgrading

```bash
go get github.com/keeper-security/secrets-manager-go/core@v1.7.0
go mod tidy
```

Tested against Go 1.16.15, 1.20.14, 1.22.x, and 1.25.0.

**Full Changelog**: https://github.com/Keeper-Security/secrets-manager-go/compare/v1.6.2...v1.7.0

---

### Breaking Changes

**Minimum Go version raised to 1.16** (previously 1.14) (KSM-616)

The SDK now uses `io` and `os` in place of the deprecated `ioutil` package. Required for `ioutil` removal; deprecation warnings began in Go 1.16. To upgrade:

1. Ensure your build environment uses Go 1.16 or later (`go version` must report `>= go1.16`).
2. Update CI/CD base images (`golang:1.15-*` and earlier will fail to build).
3. Ensure your `go.mod` declares `go 1.16` or higher.

**Behavioral changes: error handling on decryption failure**

The following functions previously returned non-nil empty stubs on decryption failure and now return `nil`. Callers that did not nil-check the return value will panic on dereference. Audit usage of:

- `NewRecordFromJson` (KSM-911)
- `NewFolderFromJson` / `NewKeeperFolder` (KSM-913)
- `NewKeeperFileFromJson` (KSM-914)
- `GetSecrets` now returns an error in the just-bound flow (first call after token exchange) if app key decryption fails, instead of returning an empty record list with a nil error. (KSM-916)

---

### Security

- Config files (`client-config.json`) are now written with mode 0600 (user-only read/write) to prevent unauthorized local access to KSM credentials. (KSM-701)
- Added transmission public key #18 for Gov Cloud Dev environment support. (KSM-745)

---

### Bug Fixes

**Decryption and data integrity**

- Records stored inside shared folders previously returned empty field values because the record was decrypted with the app key instead of the folder key. Folder-scoped records are now decrypted correctly. (KSM-756)
- `NewRecordFromJson` now returns `nil` on AES-GCM decryption failure instead of a stub record with empty fields. Applies at both failure points: record key decryption and record data decryption. (KSM-911)
- `NewFolderFromJson` and `NewKeeperFolder` now return `nil` on decryption failure instead of a stub folder with empty fields. (KSM-913)
- `NewKeeperFileFromJson` now returns `nil` on file key decryption failure instead of a stub file. `GetMeta` and `GetFileData` short-circuit immediately when the file key is empty. (KSM-914)
- `GetSecrets` now returns an error when app key decryption fails in the just-bound flow instead of silently returning an empty record list. (KSM-916)
- Malformed vault data (broken records, files, or folders) no longer crashes the SDK. Improved error messages are returned instead. (KSM-663)

**Serialization and API contract**

- `RecordField` JSON serialization now uses lowercase field tags (`type`, `label`, `value`, `required`) matching the vault wire format. Single-value fields passed as slices no longer produce double-nested arrays (e.g., `[["x"]]` instead of `["x"]`). (KSM-860)
- `RecordCreate.ToDict()` now always includes the `"custom"` key (empty list when no custom fields are set), which the backend requires. (KSM-826)
- Notation lookup no longer returns a duplicate UID error when a KSM app has access to both a record and a shortcut to the same record. Records are deduplicated by UID before the ambiguity check. (KSM-736)

**Network and runtime**

- `HTTPS_PROXY`/`HTTP_PROXY` environment variables are now honored when `ProxyUrl` is not explicitly set, matching standard `net/http` behavior. Previously these variables were silently ignored. (KSM-912)
- Replaced `strings.Cut()` (Go 1.18+) with `strings.SplitN()` throughout. Users on Go 1.16 or 1.17 would have seen build failures with the previous code.

---

### New Features

- KSM tokens with a region prefix are now parsed correctly: `US:`, `EU:`, `AU:`, `GOV:`, `JP:`, `CA:`. The prefix sets the server hostname automatically; no separate `Hostname` option is required. (KSM-565)
- HTTP proxy support added via `ClientOptions.ProxyUrl`. When `ProxyUrl` is not set, `HTTPS_PROXY`/`HTTP_PROXY` environment variables are honored automatically. (KSM-532)
- HTTP error responses now include the status code in the error message. Format: `HTTP <code>: <body>`. Code that string-matches error messages may need updating. (KSM-665)
- `links2Remove` parameter added to support removing file attachment links when updating records. (KSM-632)
- GraphSync link sharing support added for applications that resolve and share records via GraphSync. (KSM-626)
- `SetNotes` now uses UPSERT behavior: it creates the notes field if it does not exist on the record, in addition to updating it. Previously it silently no-op'd on records without an existing notes field. (KSM-583)

---

### Documentation and Examples

- New `example/custom-cache/` demonstrates a complete working TTLCache implementation using the `ICache` interface. Godoc comments added to `ICache` and `IKeyValueStorage`. (KSM-658)

---

### Downstream Compatibility

- Terraform Provider for Keeper Secrets Manager: compatible, no API changes affect the provider.
- Vault Plugin for Keeper Secrets Manager: compatible, no API changes affect the plugin.
