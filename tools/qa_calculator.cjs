'use strict';
const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const evidence=process.env.DMASH_QA_OUTPUT || '/tmp/dmash-qa-calculator';fs.mkdirSync(evidence,{recursive:true});
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.DMASH_CHROME});
 const context=await browser.newContext();const page=await context.newPage();const rows=[];
 const click=async token=>page.locator(`[data-calc-token="${token}"]`).click();
 const input=async value=>{for(const digit of value)await click(digit);await click('=');};
 const check=async(id,action,expected,fn)=>{try{await fn();rows.push({id,action,expected,status:'PASS'});}catch(e){rows.push({id,action,expected,status:'FAIL',error:e.message.slice(0,300)});}console.log(JSON.stringify(rows.at(-1)));};
 try{
 await page.goto('https://messenger.d-mash.ru/not_messenger/');
 await page.getByText('УСТАНОВКА MASTER-КОДА',{exact:true}).waitFor();
 await page.evaluate(()=>navigator.serviceWorker.ready);await page.waitForFunction(()=>!!navigator.serviceWorker.controller);
 const version={page:await page.evaluate(()=>DMASH_RELEASE.id),sw:await context.serviceWorkers()[0].evaluate(()=>RELEASE_ID),browser:browser.version()};
 await check('CALC-MASTER-SHORT','1 =','minimum 4 digits',async()=>{await input('1');assert.match(await page.locator('#history').innerText(),/МИНИМУМ 4/);});
 await click('AC');await input('3333');await page.getByText('УСТАНОВКА WIPE-КОДА',{exact:true}).waitFor();
 await check('CALC-WIPE-SHORT','2 =','minimum 4 digits',async()=>{await input('2');assert.match(await page.locator('#history').innerText(),/МИНИМУМ 4/);});
 await click('AC');await input('9876');await page.getByText('СИСТЕМА ГОТОВА',{exact:true}).waitFor();await page.waitForTimeout(1200);
 for(const digit of '0123456789')await check('CALC-'+digit,'AC '+digit,'display '+digit,async()=>{await click('AC');await click(digit);assert.equal(await page.locator('#current').innerText(),digit);});
 for(const [a,op,b,result] of [['2','+','3','5'],['9','-','4','5'],['6','*','7','42'],['8','/','2','4']])await check('CALC-'+op,`${a} ${op} ${b} =`,'display '+result,async()=>{await click('AC');await click(a);await click(op);await click(b);await click('=');await page.waitForTimeout(150);assert.equal(await page.locator('#current').innerText(),result);});
 await check('CALC-SIGN','AC 5 ±','-5',async()=>{await click('AC');await click('5');await click('±');assert.equal(await page.locator('#current').innerText(),'-5');});
 await check('CALC-PERCENT','AC 5 %','0.05',async()=>{await click('AC');await click('5');await click('%');assert.equal(await page.locator('#current').innerText(),'0.05');});
 await check('CALC-DECIMAL','AC 1 . 2 .','1.2',async()=>{await click('AC');for(const x of '1.2.')await click(x);assert.equal(await page.locator('#current').innerText(),'1.2');});
 await check('CALC-ZERO-DIV','8 / 0 =','visible calculation error',async()=>{await click('AC');await click('8');await click('/');await input('0');assert.match(await page.locator('#history').innerText(),/ОШИБКА/);});
 await check('CALC-WRONG-PIN','AC 1111 =','calculator remains visible',async()=>{await click('AC');await input('1111');assert(await page.locator('#keypad').isVisible());assert(!await page.locator('#p1').isVisible());});
 await check('CALC-UNLOCK','AC 3333 =','Account gate visible',async()=>{await click('AC');await input('3333');await page.locator('#p1').waitFor({state:'visible',timeout:60000});});
 await page.screenshot({path:path.join(evidence,'gate.png')});
 await page.reload();await page.locator('#keypad').waitFor();
 await check('CALC-RELOAD-LOCK','reload after root unlock','calculator visible',async()=>assert(await page.locator('#keypad').isVisible()));
 await check('CALC-WIPE','fresh synthetic profile 9876 =','wipe then fresh setup on revisit',async()=>{await input('9876');await page.waitForTimeout(2200);await page.goto('https://messenger.d-mash.ru/not_messenger/');await page.getByText('УСТАНОВКА MASTER-КОДА',{exact:true}).waitFor({timeout:20000});});
 fs.writeFileSync(path.join(evidence,'qa-calculator.json'),JSON.stringify({version,rows},null,2));console.log(JSON.stringify({version,pass:rows.filter(r=>r.status==='PASS').length,fail:rows.filter(r=>r.status==='FAIL').length}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
