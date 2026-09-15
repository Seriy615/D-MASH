const assert=require('node:assert/strict');
global.document={getElementById:()=>({value:'note',style:{}})};
require('../js/saved_messages.js');
const saved=DmashSavedMessages, rows=new Map(), messages=[];
const storage={masterKey:{},getAlias:async id=>id,getBox:async(_,id)=>rows.get(id),putBox:async(_,row)=>rows.set(row.alias,row.data),saveMessageGamma:async(...args)=>messages.push(args)};
(async()=>{
 const core={activeIdentity:'Account',activePeerId:saved.ID,selectPeer:async()=>{}};
 global.NodeManager=new Proxy({}, {get(){throw Error('Local chat must not access transport');}});
 assert.equal(await saved.send(core,storage,'hello',false),true);
 assert.equal(messages[0][0],saved.ID);assert.equal(messages[0][4],'LOCAL');
 rows.get(saved.ID).name='Personal';assert.equal(saved.peers([...rows.values()])[0].name,'Personal');
 assert.equal(await saved.send(core,storage,'control','SOS'),false);
 core.activeIdentity=null;assert.equal(await saved.send(core,storage,'locked',false),false);
 assert.equal(messages.length,1);
 console.log('Saved messages persist locally, preserve rename, reject handshake and locked account');
})().catch(e=>{console.error(e);process.exitCode=1;});
