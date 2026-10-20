'use strict';
const path=require('node:path'),fs=require('node:fs'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
(async()=>{const browser=await chromium.launch({headless:true,executablePath:process.env.DMASH_CHROME,args:['--no-sandbox']});try{
 const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.setContent('<main id="panel"></main>');
 await page.evaluate(()=>{globalThis.observed={starts:0,connections:0,closed:0};globalThis.root={onLock(fn){this.lock=fn;return()=>{};}};globalThis.DmashNodeRuntimeCoordinatorV4=class{constructor(root,config){observed.config=config;}host={};status(){return {state:'READY'};}async start(){observed.starts++;if(observed.fail)throw Error('PINNED_NODE_UNAVAILABLE');return this.host;}capture(){return {host:this.host,current:()=>true};}peers(){return [{token:this}];}async connect(){observed.connections++;}close(){observed.closed++;}};});
 const file=path.join(__dirname,'../D-MASH PWA/not_messenger/js/managed_node_catalog_v4.js'),source=fs.readFileSync(file,'utf8');await page.addScriptTag({content:source});await page.evaluate(()=>{globalThis.panel=DmashManagedNodeCatalogV4.mount(document.querySelector('main'),{deviceRoot:root});});
 assert.equal(await page.evaluate(()=>observed.starts),0);await page.getByRole('button',{name:'Подключить Node',exact:true}).click();await page.getByRole('status').filter({hasText:'Node подключена'}).waitFor();
 await page.evaluate(()=>root.lock());await page.getByRole('status').filter({hasText:'Node заблокирована'}).waitFor();
 await page.evaluate(()=>{observed.fail=true;});await page.getByRole('button',{name:'Подключить Node',exact:true}).click();await page.getByRole('status').filter({hasText:'PINNED_NODE_UNAVAILABLE'}).waitFor();assert.equal(await page.evaluate(()=>observed.connections),1);
 await page.evaluate(()=>panel.close());assert.equal(await page.getByRole('button',{name:'Подключить Node',exact:true}).count(),0);assert.equal(await page.evaluate(()=>observed.closed),0);assert.deepEqual(errors,[]);
 console.log(JSON.stringify({result:'PASS',sha256:crypto.createHash('sha256').update(source).digest('hex'),checks:['initial idle','actual connect click','visible success','root lock visible','failure no fallback','close preserves runtime'],limits:'Synthetic Host/root; real DOM actions only, no transport, Account cutover or production claim'}));
 }finally{await browser.close();}})().catch(error=>{console.error(error);process.exitCode=1;});
