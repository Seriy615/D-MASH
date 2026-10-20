'use strict';
// Kept importable without Playwright or browser setup for the handler regression.
async function privatePairingStep(page) {
 const refresh=page.getByRole('button',{name:'Обновить PRIVATE запросы',exact:true});
 if(await refresh.isEnabled()){await refresh.click();await page.waitForTimeout(100);}
 const accept=page.getByRole('button',{name:'Подтвердить PRIVATE контакт',exact:true}).first();
 if(await accept.isVisible()&&await accept.isEnabled())await accept.click();
}
module.exports={privatePairingStep};
