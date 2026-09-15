// Local per-chat encrypted history lifecycle and password UI.
(function (global) {
    'use strict';
    let generation = 0, grant = null, tail = Promise.resolve();
    const cipher = () => global.DmashChatCipher;
    function exclusive(work) {const result=tail.catch(()=>{}).then(work); tail=result.catch(()=>{}); return result;}
    function clear() {
        generation++; grant?.secret.fill(0); grant=null;
        global.Core?.historyPrefetch?.clear();
        global.Core?.pendingInboundByPeer?.clear();
    }
    const originals = new WeakMap();
    async function location(storage, alias, level, policy) {
        const raw=originals.get(storage).getAlias;
        if (!policy) return level==='L2' ? alias : raw.call(storage,alias,level);
        if (!/^[0-9a-f]{64}$/.test(policy.aliasEntropy||'')) throw Error('Повреждена соль чата');
        return raw.call(storage,alias+':chat:'+policy.aliasEntropy,level);
    }
    function install(storage) {
        if (originals.has(storage)) return;
        const raw={getAlias:storage.getAlias,getBox:storage.getBox,putBox:storage.putBox,deleteBox:storage.deleteBox,saveMessageGamma:storage.saveMessageGamma};
        originals.set(storage,raw);
        storage.getAlias=async function(base,level='L1') {
            const match=level==='L3' && /^([0-9a-f]{64})([0-9]+)$/.exec(base);
            if(match) {
                const peer=await raw.getBox.call(this,'blind_peers',match[1]);
                if(peer?.chatLock) return location(this,base,level,peer.chatLock);
            }
            return raw.getAlias.call(this,base,level);
        };
        for(const name of ['getBox','putBox','deleteBox']) {
            if(!raw[name]) continue;
            storage[name]=async function(table,value) {
                if(table!=='blind_secrets') return raw[name].call(this,table,value);
                const alias=name==='putBox'?value.alias:value;
                const peer=await raw.getBox.call(this,'blind_peers',alias);
                const address=await location(this,alias,'L2',peer?.chatLock);
                return raw[name].call(this,table,name==='putBox'?{...value,alias:address}:address);
            };
        }
        for (const name of ['saveMessageGamma','loadMessagesGamma','updateMessageTransportState','markInboundMessagesRead','deleteMessageGamma','deleteChatGamma']) {
            const fn=storage[name];
            if (fn) storage[name]=function(...args){return exclusive(()=>fn.apply(this,args));};
        }
    }
    async function protect(storage,id,value) {
        const peer=await storage.getBox('blind_peers',await storage.getAlias(id,'L1'));
        return peer?.chatLock ? cipher().seal(value,peer.chatLock) : value;
    }
    async function reveal(storage,id,value) {
        const peer=await storage.getBox('blind_peers',await storage.getAlias(id,'L1'));
        if (!peer?.chatLock) return value;
        if (grant?.id!==id || grant.master!==storage.masterKey) throw Error('Чат закрыт паролем');
        return cipher().open(value,grant.secret);
    }
    async function queue(storage,id,content) {
        install(storage);
        return exclusive(async()=>{
            const alias=await storage.getAlias('outbox:'+crypto.randomUUID(),'L3');
            const protectedContent=await protect(storage,id,content);
            await storage.putBox('blind_outbox',{alias,data:{peerID:id,content:protectedContent,createdAt:Date.now()}});
            const seqId=await originals.get(storage).saveMessageGamma.call(storage,id,content,false,true,'QUEUED');
            return {alias,seqId};
        });
    }
    async function change(storage,id,password,oldPassword) {
        install(storage);
        return exclusive(async()=>{
            const master=storage.masterKey, alias=await storage.getAlias(id,'L1');
            const peer=await storage.getBox('blind_peers',alias);
            if (!peer) throw Error('Чат не найден');
            const old=peer.chatLock;
            const previous=old ? await cipher().unwrap(master,oldPassword,old,alias) : null;
            const secret=global.nacl.box.keyPair().secretKey;
            try {
                const next=password ? await cipher().wrap(master,password,secret,alias) : null;
                const rows=[], removals=[], state=await storage.getBox('blind_secrets',alias);
                for(let i=1;i<=(state?.msgCount||0);i++) {
                    const oldAddress=await location(storage,alias+i,'L3',old);
                    const address=await location(storage,alias+i,'L3',next);
                    const row=await storage.getBox('blind_messages',oldAddress);
                    if(!row) continue;
                    const content=old?cipher().open(row.text,previous):row.text;
                    row.text=next?cipher().seal(content,next):content;
                    rows.push({table:'blind_messages',alias:address,blob:await storage.encryptBox(row)});
                    if(address!==oldAddress) removals.push({table:'blind_messages',alias:oldAddress});
                }
                if(state) {
                    const oldAddress=await location(storage,alias,'L2',old), address=await location(storage,alias,'L2',next);
                    rows.push({table:'blind_secrets',alias:address,blob:await storage.encryptBox(state)});
                    if(address!==oldAddress) removals.push({table:'blind_secrets',alias:oldAddress});
                }
                for(const row of await storage.getAllBoxes('blind_outbox')) {
                    if(row.peerID!==id) continue;
                    const content=old?cipher().open(row.content,previous):row.content;
                    row.content=next?cipher().seal(content,next):content;
                    rows.push({table:'blind_outbox',alias:row.alias,blob:await storage.encryptBox(row)});
                }
                if(next) peer.chatLock=next; else delete peer.chatLock;
                rows.push({table:'blind_peers',alias,blob:await storage.encryptBox(peer)});
                if(storage.masterKey!==master) throw Error('Аккаунт сменился');
                await new Promise((resolve,reject)=>{
                    const tx=storage.db.transaction(['blind_messages','blind_secrets','blind_outbox','blind_peers'],'readwrite');
                    tx.oncomplete=resolve; tx.onerror=tx.onabort=()=>reject(tx.error||Error('Изменения не сохранены'));
                    try {
                        for(const row of rows) tx.objectStore(row.table).put({alias:row.alias,blob:row.blob});
                        for(const row of removals) tx.objectStore(row.table).delete(row.alias);
                    } catch (error) {tx.abort(); reject(error);}
                });
                clear();
            } finally {secret.fill(0);previous?.fill(0);}
        });
    }
    async function allow(core,storage,id) {
        install(storage);
        const token=++generation, master=storage.masterKey;
        const alias=await storage.getAlias(id,'L1'), peer=await storage.getBox('blind_peers',alias);
        if(token!==generation || master!==storage.masterKey) return false;
        if(!peer?.chatLock) {if(grant) clear(); return true;}
        if(grant?.id===id && grant.master===master && (core.activePeerId===id||grant.once)) {grant.once=false;return true;}
        clear(); const attempt=generation;
        core.customPrompt('ПАРОЛЬ ЧАТА','Введите пароль для расшифровки:',async password=>{
            let secret;
            try {secret=await cipher().unwrap(master,password,peer.chatLock,alias);}
            catch(_) {if(attempt===generation) core.customAlert('ПАРОЛЬ ЧАТА','Неверный пароль или повреждённая защита');return;}
            if(attempt!==generation||storage.masterKey!==master) {secret.fill(0);return;}
            grant={id,master,secret,once:true};await core.selectPeer(id);
        },{inputType:'password'});
        return false;
    }
    async function configure(core,storage) {
        const id=core.activePeerId, master=storage.masterKey;
        if(!id) return;
        const peer=await storage.getBox('blind_peers',await storage.getAlias(id,'L1'));
        const current=()=>core.activePeerId===id&&storage.masterKey===master;
        const setNew=old=>core.customPrompt('ПАРОЛЬ ЧАТА','Новый пароль (пусто — убрать защиту). Без пароля восстановить историю нельзя.',async password=>{
            if(!current()) return;
            const commit=async()=>{if(!current()) return;await change(storage,id,password,old);if(current()) core.closeChat();};
            if(!password) {await commit();return;}
            core.customPrompt('ПОВТОР ПАРОЛЯ','Повторите новый пароль:',async confirmation=>{
                if(confirmation!==password) throw Error('Пароли не совпадают');await commit();
            },{inputType:'password'});
        },{inputType:'password'});
        if(peer?.chatLock) core.customPrompt('ТЕКУЩИЙ ПАРОЛЬ','Введите текущий пароль:',old=>{if(current()) setNew(old);},{inputType:'password'});
        else setNew(null);
    }
    global.DmashChatPassword=Object.freeze({allow,configure,change,protect,reveal,clear,install,exclusive,location,queue});
})(typeof window==='undefined'?globalThis:window);
