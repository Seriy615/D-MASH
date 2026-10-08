const assert=require('node:assert/strict');
require('../js/file_vault.js');
const root={generation:1};
globalThis.DeviceRoot={state:root};
const keys={pub_hex:'a'.repeat(2300),server_id:'b'.repeat(64)};
const core={keys,blindSalt:new Uint8Array(32),activeIdentity:'synthetic-account',
    bytesToHex:bytes=>Buffer.from(bytes).toString('hex')};
const storage={db:{objectStoreNames:{contains:()=>true}},masterKey:{}};
const vault=new DmashFileVault(core,storage);
const captured=vault.capture();
assert.equal(captured.owner,keys.server_id,'owner is the stable signing identity, not the composite bundle');
captured.check();
const MiB=1024*1024, peer='c'.repeat(64), other='d'.repeat(64);
vault.ensureCapacity([{peer,size:64*MiB,inbound:true}],peer,64*MiB,true);
assert.throws(()=>vault.ensureCapacity([{peer,size:128*MiB,inbound:true}],peer,1,true),
    /контакта/,'a confirmed peer cannot consume unlimited receiver storage');
assert.throws(()=>vault.ensureCapacity([{peer:other,size:256*MiB,inbound:false}],peer,1,true),
    /аккаунта/,'all files share a bounded Account quota');
core.keys={...keys};
assert.throws(()=>captured.check(),/Account changed/,'a captured file cannot cross an Account switch');
core.keys=keys;
DeviceRoot.state={generation:2};
assert.throws(()=>captured.check(),/Account changed/,'a captured file cannot cross a DeviceRoot switch');
console.log('file_vault_owner.test.js: signing owner and Account/DeviceRoot guards passed');
