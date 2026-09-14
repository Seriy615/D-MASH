const assert = require('node:assert/strict');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
    const browser = await chromium.launch({headless:true, channel:'chrome',
        args:['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--allow-loopback-in-peer-connection', '--disable-features=WebRtcHideLocalIpsWithMdns', '--autoplay-policy=no-user-gesture-required']});
    try {
        const pages = [];
        for (let i=0;i<2;i++) {
            const context = await browser.newContext();
            const page = await context.newPage(); pages.push(page);
            await page.goto(process.argv[2]);
            for (const name of ['call_signaling','call_session','call_runtime','file_channel','file_session','file_runtime'])
                await page.addScriptTag({url:'/js/' + name + '.js'});
            await page.evaluate(() => {
                const create = DmashFileSession.create;
                window.events = [];
                DmashFileSession.create = options => {
                    const session = create({...options, useRemoteIceServers:false});
                    const make = session._createPeer.bind(session);
                    session._createPeer = () => {make();
                        const pc = session.pc, handler = pc.onconnectionstatechange;
                        pc.onconnectionstatechange = event => {events.push({rtc:pc.connectionState,ice:pc.iceConnectionState}); return handler?.(event);};
                    };
                    const bind = session.bindChannel.bind(session);
                    session.bindChannel = channel => {events.push({label:channel.label,ordered:channel.ordered,
                        retransmits:channel.maxRetransmits,lifetime:channel.maxPacketLifeTime}); bind(channel);};
                    session.onerror = error => events.push(error.name);
                    return session;
                };
                navigator.mediaDevices.getUserMedia = () => {throw Error('File requested microphone');};
                window.Core = {activePeerId:'fixture-recipient',
                    async sendMessage(message) {this.sent = message; return true;},
                    customAlert(title,message) {throw Error(message);}};
                window.NodeManager = {async selectCallService(options) {
                    if (!options.file) throw Error('File capability not checked');
                    return location.origin.replace('http:', 'ws:') + '/signal/v1';
                }};
            });
        }
        const request = await pages[0].evaluate(async () => {
            const bytes = new Uint8Array(8 * 1024 * 1024 + 13);
            for (let i=0;i<bytes.length;i++) bytes[i]=i % 251;
            if (!await DmashFileRuntime.send(Core,new File([bytes],'integration.bin'))) throw Error('File sender failed');
            if (Core.sent.type !== 'voip_file_request') throw Error('File data entered chat');
            return Core.sent.request;
        });
        assert.equal(request.version, 1);
        assert.equal(request.resumable, false);
        await pages[1].evaluate(request => DmashFileRuntime.incoming(Core,request,'fixture-sender'), request);
        await pages[1].getByRole('button', {name:'Принять', exact:true}).click();
        try {
            for (const page of pages) {
                await page.waitForFunction(() => Core._fileTransfer?.finished || Core._fileTransfer?.session?.closed, null, {timeout:45000});
                assert(await page.evaluate(()=>Core._fileTransfer.finished));
            }
        } catch (error) {
            console.error(JSON.stringify(await Promise.all(pages.map(p=>p.evaluate(()=>({status:Core._fileTransfer?.status.textContent,
                connection:Core._fileTransfer?.session?.pc?.connectionState, index:Core._fileTransfer?.session?.pipe?.index,
                closed:Core._fileTransfer?.session?.closed,events}))))));
            throw error;
        }
        const received = await pages[1].evaluate(async () => {
            const data = await (await fetch(Core._fileTransfer.url)).arrayBuffer();
            const digest = new Uint8Array(await crypto.subtle.digest('SHA-256',data));
            return {size:data.byteLength, sha256:Array.from(digest,x=>x.toString(16).padStart(2,'0')).join('')};
        });
        assert.equal(received.size,request.size_bytes); assert.equal(received.sha256,request.sha256);
        for (const page of pages) await page.evaluate(() => DmashFileRuntime.cancel(Core));
        for (const page of pages) assert(await page.evaluate(() => !Core._fileTransfer && !document.querySelector('.dmash-file-transfer')));
        console.log(JSON.stringify({passed:true, bytes:received.size, sha256Verified:true,
            mode:'PWA file controller, native Chrome DataChannel, local signaling; fixture invitation delivery; direct ICE'}));
    } finally {await browser.close();}
})().catch(error => {console.error(error); process.exitCode=1;});
