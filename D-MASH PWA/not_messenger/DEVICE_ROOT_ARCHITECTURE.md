# DeviceRoot foundation (v1)

## Scope and security boundary

`DeviceRoot` is a **32-byte CSPRNG secret per browser installation**, not an Account secret and not a network identifier. It is generated exclusively by `crypto.getRandomValues()` and stays only in memory while unlocked. It is persisted in a dedicated IndexedDB database (`dmash_device_root_v1`) as AES-256-GCM ciphertext, with a unique random Argon2id wrap salt and fixed authenticated associated data `dmash/device-root-wrap/v1`.

The existing calculator passphrase unlocks this wrapping layer in v1. It is **not input to any DeviceRoot derivation**. The database has no Account-derived vault/master-key wrapping and no raw root, child root, or private key plaintext.

Browser IndexedDB/WebCrypto are *not* a Secure Enclave and provide no protection against active same-origin malicious JavaScript/XSS, browser profile theft, or a compromised unlocked process. WebAuthn PRF is deliberately not claimed: it is not uniformly supported, and no fallback may silently weaken an enrolled PRF policy. A future explicit enrollment/recovery policy may add it.

## Threat model and recovery

| Event | Behavior |
|---|---|
| normal reload/restart/offline | decrypt existing record; same Device identity and persisted ML-KEM material |
| wrong passphrase, corrupted record, unavailable/blocked/write-failed IDB | explicit failure; no fresh DeviceRoot or private-key replacement |
| clear browser/site data | root is irrecoverable; user must use an explicit recovery/re-enrollment flow (not implemented) |
| pre-DeviceRoot Gamma vault | detected by IDB inventory; legacy Account workflow stays intact and DeviceRoot creation is withheld pending explicit migration |

Revocation is an explicit future protocol operation: local wiping alone cannot tell peers/nodes that an old device credential is revoked. No revocation claim is made by this foundation.

## Hierarchy and encoding

```
CSPRNG DeviceRoot (32 B)
  └── HKDF-SHA-256, salt = 32 zero bytes, L = 32 B
       info = u32be(version) || u32be(domain UTF-8 length) || domain UTF-8
              || u32be(context UTF-8 length) || context UTF-8
       ├── dmash/device-identity-ed25519 / v1 / "" -> 32 B Ed25519 seed
       ├── dmash/device-identity-x25519  / v1 / "" -> 32 B X25519 secret
       ├── dmash/device-storage           / v1 / context
       ├── dmash/device-pairing           / v1 / context
       ├── dmash/device-routing           / v1 / context
       ├── dmash/device-transport-auth    / v1 / context
       └── dmash/device-mlkem-seed-root   / v1 / algorithm name
            └── AES-GCM encrypted randomly generated ML-KEM-768 material
```

Ed25519/X25519 are derived only through their library-approved 32-byte seed/secret APIs. This code **does not invent deterministic ML-KEM private-key derivation**; generated ML-KEM material is stored encrypted under its own domain-derived wrapping key and is never regenerated after corruption.

`DeviceID = d1_ + base64url(SHA-256("dmash/device-id/v1" || Ed25519_public || X25519_public))`. It is public/pseudonymous and specifically **not** `hash(DeviceRoot)`.

## Migration and wire boundary

This is a foundation migration, intentionally not a wire migration. Existing Account-derived Ed25519/X25519 and Gamma encryption retain their legacy behavior for compatibility. New Device keys are held separately at `Core.device`; no DeviceRoot, child root, wrap key, secret seed, encrypted root record, or derived private material is added to WebSocket payloads, QR descriptors, logs, diagnostics, or telemetry. The public DeviceID is also not transmitted until a separately designed device-auth protocol and acceptance suite exist.

The legacy-vault detector uses `indexedDB.databases()` before creating a root. Browsers without that non-mutating inventory API fail closed for migration rather than guessing. An explicit future migration must authenticate the legacy account, create DeviceRoot, bind the new device public credential through a protocol migration, and preserve/rotate routes under a defined recovery policy.

## Deterministic vector

For root `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`, domain `dmash/device-storage`, version `1`, context `account:alpha`, the 32-byte output is:

```
9ea96294abd4d5642d68e43357e2c098100c759d237a71c7226bb5cb79d160ef
```

`tests/device_root.test.js` verifies this vector plus root stability, encrypted-at-rest non-exposure, separation by domain/version/context, wrong-PIN failure, legacy migration safety, and write-failure behavior.
