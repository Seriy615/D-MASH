'use strict';
// Encrypted, bounded durable relationships. Socket admission is never cached here.
(function(global) {
    const text = value => new TextEncoder().encode(value);
    const hex = bytes => Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
    const field = (value,length) => {
        if(typeof value !== 'string' || !(new RegExp('^[0-9a-f]{'+length+'}$')).test(value)) throw Error('Invalid relationship field');
        return value;
    };
    class NodeRelationships {
        static async openForDevice(deviceRoot, localId, options={}) {
            const session=deviceRoot?.state;
            if(!session?.root) throw Error('Device must be unlocked');
            let key;
            try {
                key=await deviceRoot.derive(session.root,'dmash/node-storage',4,'directional-relationships');
                if(deviceRoot.state!==session) throw Error('Device session changed');
                return await this.open(key,localId,{...options,isCurrent:()=>deviceRoot.state===session && (options.isCurrent?.()??true)});
            } finally {key?.fill(0);}
        }
        static async open(storageKey, localId, {databaseName='dmash_node_relationships_v4', maxRelationships=4096, isCurrent=()=>true}={}) {
            field(localId,64);
            if(!(storageKey instanceof Uint8Array) || storageKey.length!==32 || !Number.isInteger(maxRelationships) || maxRelationships<1 || maxRelationships>65536) throw Error('Invalid Node storage parameters');
            const store = new NodeRelationships();
            store.localId=localId; store.maxRelationships=maxRelationships; store.isCurrent=isCurrent;
            store.transactions=new Set(); store.closed=false;
            try {
                const base = await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']);
                const derive = label => crypto.subtle.sign('HMAC',base,text(label));
                const alias = new Uint8Array(await derive('D-MASH|NODE-RELATIONSHIP-ALIAS|V4'));
                const encryption = new Uint8Array(await derive('D-MASH|NODE-RELATIONSHIP-STORAGE|V4'));
                try {
                    store.aliasKey=await crypto.subtle.importKey('raw',alias,{name:'HMAC',hash:'SHA-256'},false,['sign']);
                    store.encryptionKey=await crypto.subtle.importKey('raw',encryption,'AES-GCM',false,['encrypt','decrypt']);
                } finally {alias.fill(0);encryption.fill(0);}
                store.check();
                store.db=await new Promise((resolve,reject)=>{
                    const request=global.indexedDB.open(databaseName,1);
                    request.onupgradeneeded=()=>request.result.createObjectStore('relationships',{keyPath:'key'});
                    request.onsuccess=()=>{if(store.closed){request.result.close();reject(Error("Node storage session changed"));}else resolve(request.result);};
                    request.onerror=()=>reject(Error('Node relationship storage unavailable'));
                    request.onblocked=()=>reject(Error('Node relationship storage blocked'));
                });
                store.db.onversionchange=()=>store.close();
                const binding={version:4,localId};
                for(let attempt=0;attempt<8;attempt++) {
                    const row=await store.read('binding');
                    if(row) {
                        const value=await store.decrypt(row);
                        if(JSON.stringify(value)!==JSON.stringify(binding)) throw Error('Node relationship store identity changed');
                        return store;
                    }
                    // Metadata creation is refused if any orphan relationships exist.
                    if(await store.cas('binding',null,await store.encrypt('binding',binding),true)) return store;
                }
                throw Error('Node relationship storage contention');
            } catch(error) {store.close();throw error;}
        }
        check() {if(this.closed || !this.isCurrent()) throw Error('Node storage session changed');}
        transaction(mode,body) {
            this.check();
            return new Promise((resolve,reject)=>{
                const tx=this.db.transaction('relationships',mode);
                this.transactions.add(tx);
                let result;
                tx.oncomplete=()=>{this.transactions.delete(tx);try{this.check();resolve(result);}catch(error){reject(error);}};
                tx.onabort=tx.onerror=()=>{this.transactions.delete(tx);reject(Error('Node relationship transaction failed'));};
                try {body(tx.objectStore('relationships'),value=>{result=value;},tx);}
                catch(error) {tx.abort();reject(error);}
            });
        }
        read(key) {return this.transaction('readonly',(objectStore,done)=>{objectStore.get(key).onsuccess=event=>done(event.target.result||null);});}
        cas(key,revision,row,binding=false) {
            return this.transaction('readwrite',(objectStore,done,tx)=>{
                objectStore.get(key).onsuccess=event=>{
                    const current=event.target.result;
                    if((current?.revision??null)!==revision) {done(false);return;}
                    const write=()=>{try{this.check();objectStore.put({...row,key,revision:(revision??0)+1});done(true);}catch(_){tx.abort();}};
                    if(current) {write();return;}
                    objectStore.count().onsuccess=event=>{
                        if((binding && event.target.result!==0) || (!binding && event.target.result>=this.maxRelationships+1)) {tx.abort();return;}
                        write();
                    };
                };
            });
        }
        async encrypt(key,value) {
            this.check();
            const iv=crypto.getRandomValues(new Uint8Array(12));
            const bytes=text(JSON.stringify(value));
            try {
                const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text('D-MASH|NODE-RELATIONSHIP|V4|'+key)},this.encryptionKey,bytes);
                this.check();return {iv,ciphertext};
            } finally {bytes.fill(0);}
        }
        async decrypt(row) {
            this.check();
            let plaintext;
            try {
                plaintext=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:row.iv,additionalData:text('D-MASH|NODE-RELATIONSHIP|V4|'+row.key)},this.encryptionKey,row.ciphertext));
                this.check();return JSON.parse(new TextDecoder().decode(plaintext));
            } catch(_) {throw Error('Node relationship storage unreadable; recovery required');}
            finally {plaintext?.fill(0);}
        }
        async relationship(peerId,{inbound=null}={}) {
            this.check();field(peerId,64);
            if(peerId===this.localId) throw Error('Self relationship forbidden');
            if(inbound!==null) field(inbound,32);
            const pair=Uint8Array.from((this.localId+peerId).match(/../g),b=>parseInt(b,16));
            const key=hex(new Uint8Array(await crypto.subtle.sign('HMAC',this.aliasKey,pair)));
            this.check();
            for(let attempt=0;attempt<16;attempt++) {
                const row=await this.read(key);
                const value=row?await this.decrypt(row):{version:4,localId:this.localId,peerId,outbound:hex(crypto.getRandomValues(new Uint8Array(16))),inbound:null};
                if(Object.keys(value).sort().join(',')!=='inbound,localId,outbound,peerId,version' || value.version!==4 || value.localId!==this.localId || value.peerId!==peerId) throw Error('Invalid relationship binding');
                field(value.outbound,32);
                if(value.inbound!==null) {field(value.inbound,32);if(value.inbound===value.outbound) throw Error('Direction collision');}
                if(inbound!==null) {
                    if((value.inbound!==null && value.inbound!==inbound) || value.outbound===inbound) throw Error('Node relationship changed; explicit recovery required');
                    value.inbound=inbound;
                }
                if(await this.cas(key,row?.revision??null,await this.encrypt(key,value))) return {outbound:value.outbound,inbound:value.inbound};
            }
            throw Error('Node relationship storage contention');
        }
        close() {
            this.closed=true;
            for(const tx of this.transactions||[]) {try{tx.abort();}catch(_){}}
            this.transactions?.clear();
            this.db?.close();this.db=null;this.aliasKey=null;this.encryptionKey=null;
        }
    }
    global.DmashNodeRelationshipsV4=NodeRelationships;
    if(typeof module!=='undefined') module.exports=NodeRelationships;
})(typeof window!=='undefined'?window:globalThis);
