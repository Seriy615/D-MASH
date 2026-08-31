# Device identity migration and DMP-C device auth (v1)

## Invariant

| Entity | Purpose | Transport exposure |
|---|---|---|
| Account identity | Existing logical user/contact identity; legacy message signatures, X25519, ML-KEM and Gamma state | Never in `DEVICE_AUTH_V1` |
| Device identity | Installation-scoped public device keys, rooted in DeviceRoot | Not sent as a global DeviceID |
| TransportAuthIdentity | Node-scoped Ed25519 key derived from DeviceRoot | Public key only, to that challenged Node |

DeviceRoot, passphrases, account private keys, child roots and DeviceBinding records never enter DMP-C frames.

## Legacy migration

`not_started -> in_progress -> complete` is recorded in the separate
`dmash_device_root_v1/device_root` IndexedDB store. Boot initially recognizes a
legacy Gamma vault but creates no root. Only after the legacy Account Argon2
unlock has recreated and verified its Ed25519 secret key can `migrateLegacy()`:

1. persist `in_progress`;
2. create/wrap/persist one DeviceRoot;
3. derive device public keys;
4. create a local signed DeviceBinding;
5. reopen/decrypt the persisted root;
6. atomically write root migration state and the complete marker.

Restarting at `in_progress` reopens the same root and completes its same
binding. A complete marker without a root, a corrupt root, or an invalid
binding fails closed. Account keys, AccountID, contacts, conversation vault and
contact fingerprints are untouched. There is no wire migration message.

`DeviceBindingV1` is a local, versioned proof signed by the legacy Account
Ed25519 key over canonical pipe-delimited public fields: protocol label,
version, Account public key, device signing public key, device agreement public
key, and creation time. It confirms local authorization, but is not sent until
a future Account↔Device protocol needs it.

## DMP-C v2 DEVICE_AUTH_V1

The Node sends a fresh challenge:

```
{ protocol: DMP-C, version: 2, auth_mode: DEVICE_AUTH_V1,
  node_id, session_id, nonce, expires_at }
```

The PWA derives a node-scoped Ed25519 seed via existing DeviceRoot HKDF domain
`dmash/device-transport-auth`, context `DMP-C|2|<lowercase NodeID>`. It signs
the canonical transcript:

```
DMP-C|2|DEVICE_AUTH_V1|node_id|session_id|server_nonce|client_nonce|expires_at
```

The client sends only `auth_mode`, this node-specific public key, a fresh
client nonce, and the signature. The gateway verifies exact version, NodeID,
server challenge, session, client nonce format, expiry, and Ed25519 signature
before creating an authenticated WebSocket session. Principal data is RAM-only:
the gateway persists no DeviceRoot, Account identity, passphrase, contact graph
or central device database.

The transcript binds a captured AUTH to one server nonce/session/NodeID/expiry;
replay against a fresh challenge fails. A malformed or unsupported device-auth
challenge fails the client connection. A DeviceRoot-active PWA does not send a
legacy Account AUTH fallback. Legacy v1 helper code remains only for explicit
compatibility testing and is not accepted by the v2 endpoint.

## Privacy and lifecycle

Different NodeIDs derive different public transport keys, so independent Nodes
cannot use a shared global DeviceID to correlate an installation through this
protocol. A malicious Node may still correlate reconnects to itself, as required
for its own transport session. NodeID authenticity is currently supplied by the
existing trusted endpoint configuration/challenge model; unauthenticated
endpoint substitution is outside this cutover and must be addressed by node
pinning in a later milestone.

Reload/restart preserves encrypted DeviceRoot and produces the same
node-scoped key. Account lock/logout clears root and key material from runtime
memory but does not delete encrypted device storage. Full wipe is the existing
explicit remove-device equivalent; a dedicated remove-device command is future
work.
