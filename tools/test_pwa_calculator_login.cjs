'use strict';
const assert = require('node:assert/strict');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
    const browser = await chromium.launch({executablePath: process.env.DMASH_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true});
    let page;
    try {
        const context = await browser.newContext();
        page = await context.newPage(); const errors = [];
        page.on('pageerror', e => {errors.push(e.message); console.error(e.message);});
        page.on('console', message => { if (/WARN|ERR|failed/i.test(message.text())) console.error(message.text()); });
        await page.goto(process.argv[2]);
        const digits = async value => {
            for (const digit of value) await page.getByRole('button', {name: digit, exact: true}).click();
            await page.getByRole('button', {name: '=', exact: true}).click();
        };
        await page.getByText('УСТАНОВКА MASTER-КОДА', {exact:true}).waitFor();
        await digits('3333');
        await page.getByText('УСТАНОВКА WIPE-КОДА', {exact:true}).waitFor();
        await digits('9876');
        await page.getByText('СИСТЕМА ГОТОВА', {exact:true}).waitFor();
        await page.waitForTimeout(1200); // setup's one-second calculator reset
        await digits('3333');
        await page.locator('#p1').waitFor({state:'visible'});
        const login = async () => {
            await page.locator('#p1').fill('browser-login-regression');
            await page.locator('#p2').fill('Test-only-login-2026!');
            await page.getByRole('button', {name:'ВОЙТИ', exact:true}).click();
            await page.getByText('Избранное', {exact:true}).waitFor({timeout:20000});
        };
        await login();
        console.log('PASS initial Account login');
        await page.getByText('Избранное', {exact:true}).click();
        await page.locator('#msgInput').fill('Persistent calculator note');
        await page.getByRole('button', {name:'SEND', exact:true}).click();
        await page.waitForFunction(() => document.querySelector('#log')?.textContent.includes('Persistent calculator note'));
        console.log('PASS local note');
        // Exercise the real panic lifecycle; crypto and storage are not replaced.
        await page.evaluate(() => Core.terminateSession());
        await page.getByRole('button', {name:'3', exact:true}).waitFor();
        await digits('3333');
        await page.locator('#p1').waitFor({state:'visible'});
        await login();
        await page.getByText('Избранное', {exact:true}).click();
        await page.waitForFunction(() => document.querySelector('#log')?.textContent.includes('Persistent calculator note'));
        if (process.env.DMASH_TEST_EMS === '1') {
            await page.getByRole('button', {name:'Настройки', exact:true}).click();
            await page.getByRole('button', {name:'УЗЛЫ И ПОДКЛЮЧЕНИЕ', exact:true}).click();
            await page.getByRole('button', {name:'ЗАПРОСИТЬ УЗЕЛ', exact:true}).click();
            await page.waitForFunction(() => [...NodeManager.connections.values()].some(c => c.dnssReadyState === 'ready'), null, {timeout:240000});
            const result = await page.evaluate(async () => {
                const c = NodeManager.connectedConnections()[0];
                const status = await c.client.request('STATUS');
                const mailbox = await c.client.request('PULL');
                return {url:c.socket.url, status:status.type, mailbox:mailbox.type};
            });
            assert.match(result.url, /\/v3$/);
            assert.equal(result.status, 'STATUS');
            assert.equal(result.mailbox, 'MAILBOX_DRAIN_RESULT');
            console.log(JSON.stringify(result));
        }
        assert.deepEqual(errors, []);
        console.log('PASS real calculator setup, Account login, local note, panic lock and re-login; no crypto or login stubs');
    } catch (error) {
        if (page) console.error(await page.evaluate(() => ({history:document.querySelector('#history')?.textContent, gate:document.querySelector('#gate-status-text')?.textContent, mode:ui.mode, calculator:document.querySelector('#app-container')?.getAttribute('style'), settings:document.querySelector('#settings-layer')?.getAttribute('style'), body:document.body.innerText.slice(0,1200)})));
        throw error;
    } finally { await browser.close(); }
})().catch(error => {console.error(error);process.exitCode=1;});
