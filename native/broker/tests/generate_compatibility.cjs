const fs = require('node:fs');
const repo = process.argv[2];
global.nacl =
    require(repo + '/D-MASH PWA/not_messenger/js/vendor/nacl-fast.min.js');
const {DeviceRoot} =
    require(repo + '/D-MASH PWA/not_messenger/js/device_root.js');
(async () => {
  const root = new Uint8Array(32).fill(7), salt = new Uint8Array(16).fill(3),
        iv = new Uint8Array(12).fill(4);
  const keys = {
    d : '5564f7006653f1592f41f5cc70074135d716c2f4967be0f18ee869412ebfbe34',
    id : 'b890ec8c8f2b3217ced9eb117fa46330b80d0795d1ee6e44bf3d10320283cb45'
  };
  const b64 = x => Buffer.from(x).toString('base64');
  const seal = async (key, aad, bytes) => b64(await crypto.subtle.encrypt(
      {name : 'AES-GCM', iv, additionalData : new TextEncoder().encode(aad)},
      await crypto.subtle.importKey('raw', key, 'AES-GCM', false,
                                    [ 'encrypt' ]),
      bytes));
  const materials = {};
  for (const [name, byte] of [[ 'node-ed25519-pow-v4', 8 ],
                              [ 'node-base-ncrh-v4', 9 ]])
    materials[name] = {
      iv : b64(iv),
      ciphertext : await seal(
          await DeviceRoot.derive(root, 'dmash/device-mlkem-seed-root', 1,
                                  name),
          'dmash/device-material/v1|' + name, new Uint8Array(32).fill(byte))
    };
  const records = {};
  for (const [name, type, aad] of [[ 'legacy_d', 'd', 1 ],
                                   [ 'legacy_id', 'id', 1 ],
                                   [ 'modern_id', 'id', 2 ]]) {
    records[name] = {
      id : 'root',
      version : 1,
      wrap : 'argon2id-aes-256-gcm-v' + aad,
      wrapSalt : b64(salt),
      iv : b64(iv),
      wrappedRoot : await seal(Buffer.from(keys[type], 'hex'),
                               'dmash/device-root-wrap/v' + aad, root),
      materials,
      opaqueMetadata : {mustSurvive : 'synthetic encrypted owner metadata'}
    };
    if (aad === 2) {
      records[name].wrapKdf = {...DeviceRoot.credentialProfile};
      records[name].credentialRevision = 2;
      records[name].credentials = {
        version : 1,
        state : 'ready',
        legacyCleanup : 'complete',
        wipe : null,
        wipeDisabledReason : 'not-configured'
      }
    }
  }
  const fixture = {
    scope :
        'SYNTHETIC ONLY; no production identities/secrets. Node seed is deliberately not mined; structural crypto scope only, actor authorization separate.',
    pin : 'synthetic-only-master',
    deviceId : (await DeviceRoot.deviceIdentity(root)).deviceId,
    expectedTransport : {
      nodeSeed : Buffer.alloc(32, 8).toString('hex'),
      baseNcrh : Buffer.alloc(32, 9).toString('hex'),
      storageKey :
          Buffer
              .from(await DeviceRoot.derive(root, 'dmash/node-storage', 4,
                                            'directional-relationships'))
              .toString('hex')
    },
    records
  };
  fs.writeFileSync(repo + '/native/broker/tests/compatibility.json',
                   JSON.stringify(fixture, null, 2) + '\n')
})().catch(e => {
  console.error(e);
  process.exitCode = 1
});
