# Native Account private pairing

This is the typed credential-host API backed by the original
`DmashPublicAccountOrchestratorV4` private flow. It uses managed Node ownership,
`private-v1` bootstrap, actual signed journal preparation/commit/activation and
Account-owned static KEM. Node receives scoped discovery/recipient material,
public signed bundles and ciphertext; Account signing/KEM secrets remain in the
Account process.

Candidate03 author component acceptance proves fresh Root/Account setup,
concurrent activation and bilateral text. Ordinary client UI, browser/native
interoperability, compressed link/QR import and public contact intake are **not
accepted by that proof**.

## Transport and result types

Use the existing authenticated credential-host session and four-byte BE framed
JSON RPC. These methods do not introduce another socket, token or transport.
The ordinary response is `{v:1,id,ok:true,result:{value,rows}}`; the host maps
the typed `AccountResult` success/code to the outer RPC result.
Errors carry the existing fixed `code`; show a useful error and keep the user
selection/input for retry. Never log credential frames or full bundles.

A `Peer` is the 64 lowercase hexadecimal Account signing public key. An `Id` is
64 lowercase hexadecimal characters. A `Bundle` is the **original canonical
signed `DMASH_PAIRING_V2` JSON string**, not a parsed/re-serialized object and
not an arbitrary URL. Native currently accepts raw bundle copy/paste. Do not
silently treat the browser's compressed share link as a raw bundle.

| RPC method | Params | Successful result |
| --- | --- | --- |
| `account.pairingCreate` | `{expectedPeer?:Peer}`; omit/null for an untargeted offer | `value:{id:Id,bundle:Bundle,accountPublic:Peer}` |
| `account.pairingInspect` | `{bundle:Bundle,expectedPeer?:Peer}` | `value:{accountPublic:Peer,expiresAt:number,intendedPeer:Peer\|null,bundle:Bundle}` |
| `account.pairingRequest` | `{bundle:Bundle,expectedPeer:Peer}` | `value:{id:Id,state:'PRIVATE_REQUEST_SENT',ready:false}` |
| `account.pairingOffers` | `{}` | `rows:Offer[]` |
| `account.pairingAdvance` | `{id:Id,exchangeId:Id,requestDigest:Id,expectedPeer:Peer,deny:boolean,name?:string}` | `value:Advance` |

`Offer` is either `{id,bundle,requests:Request[]}` or
`{id,pending:true,code}`. A pending local material slot is not an incoming
contact and must not be automatically accepted or discarded. `Request` includes
`exchangeId,requestDigest,remoteAccount,expiresAt,state,direction,receipts`;
`direction` is `INBOUND` or `OUTBOUND`. `PENDING` requires explicit selection;
`SELECTED` means a previous local selection. `DENIED` and `EXPIRED_SELECTED`
remain visible and must not be accepted as fresh invitations. Treat serialized
request/receipt fields as signed protocol data, not presentation markup.

`Advance` may be `{state:'DENIED',ready:false}`,
`{state:'WAITING_ACCEPT_RECEIPT',ready:false}` or
`{state:'WAITING_BILATERAL_RECEIPTS',ready:false}`. Final success is
`{state:'ACCOUNT_ROUTE_ACTIVE',ready:true,peer,bindingDigest,generation,
contactPublished:true,sessionEstablished:boolean}`. A route being active is
not proof of E2EE establishment or recipient delivery.

## Normal client flow

1. Unlock Root and log in to the selected Account through the ordinary host
   APIs. Start Node with `node.enable`; do not require another Account login
   merely to keep Node running. Pairing requires initialized `private-v1` Node.
2. To offer, call `pairingCreate`, then display/copy its exact `bundle`. If the
   other Account public key is known, pass `expectedPeer` to target the offer.
3. To import, call `pairingInspect`. Display the authenticated sender key,
   intended recipient and expiry. Ask the user to select/confirm the intended
   peer, then call `pairingRequest` with that sender as `expectedPeer`.
4. Refresh `pairingOffers`. On the user's Accept action pass that exact row's
   `id/exchangeId/requestDigest`, the selected peer and a nonempty contact name
   to `pairingAdvance`. Reject uses `deny:true` and does not need a name.
5. A waiting result means remote signed control has not arrived. Refresh and
   advance the **same selected row**; do not create a new request/offer on each
   poll. The native facade immediately starts E2EE after local final activation;
   it does not wait for the other UI to become ready first.
6. Use `account.sync` to progress the normal Account runtime and inspect its
   peer status. With the durable first-send extension, `account.sendText` before
   `ESTABLISHED` returns `accepted:true,transportState:'HANDSHAKE_PENDING'` after
   encrypted Account commit. Pending text is visible in history and flushes
   automatically after establishment, including logout/owner-crash recovery.
   Do not require a second click. Retry the exact same operation ID/text only
   when reconciling an uncertain local RPC outcome; do not mint another ID.
   See [model contract](CLIENT_ADAPTER_CONTRACT.md). `NODE_ACCEPTED` is not a
   recipient ACK. Candidate03's earlier false/pending response is historical.
7. Use ordinary `account.contacts` and `account.history` after publication.
   Account logout closes its adapters and owner sessions but preserves Node and
   committed routes/history. Root lock stops Node through the resident owner.

Example selection (values come from the inspected offer/current request):

```json
{"v":1,"id":"accept-1","method":"account.pairingAdvance","params":{"id":"<offer-id>","exchangeId":"<request-exchange-id>","requestDigest":"<request-digest>","expectedPeer":"<confirmed-peer-public-key>","deny":false,"name":"Alice"}}
```

## Integration constraints

Apply the isolated implementation commits in order:
`f50e82c`, `a4b5251`, `7b92a86`, `52d641a`, `a8b36ee`, then fixture/evidence
`6e66764`, `1f5e5db`. The subsequent first-send extension is `562941a`;
its actual no-caller-retry/crash gate uses pending-send candidate01. Base includes the accepted stable native job-expiry fix
`f187474`; preserve it when merging Account changes. `a8b36ee` touches only host
pairing dispatch and should merge alongside broker pause/status work without
copying an older whole host file. Build **both** credential host and Node from
the coherent source: an older Node does not advertise/provide the bootstrap
RPCs, and an older host lacks the typed Account facade.

The three canonical PWA source changes are narrow default-compatible seams:
optional trusted bootstrap store, private profile/static-KEM adapter injection,
and targeted-requester parsing context. Default browser storage/KEM stay the
original implementations. Release/SW metadata, browser regression and deployment
are owned by the integrator; native component proof does not publish the PWA.
Never overwrite platform UI/CI files when integrating this series.

Native currently advertises `private-v1`, not `public-v1`. Public contact intake
requires the original separate public bootstrap runtime and typed neutral
registration/request/accept/confirm APIs before enabling its UI. The private
methods above are not a substitute for public intake or synthetic route setup.
