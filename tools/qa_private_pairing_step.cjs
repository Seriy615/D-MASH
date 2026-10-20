'use strict';
// Kept importable without Playwright or browser setup for the handler regression.
async function privatePairingStep(page,{deadline,onAction=()=>{}}) {
 const remaining=()=>{const ms=deadline-Date.now();if(!Number.isFinite(ms)||ms<=0)throw Error('PRIVATE pairing deadline');return ms;};
 const idle=()=>page.locator('[data-node-account-panel][aria-busy="true"]').waitFor({state:'hidden',timeout:remaining()});
 await page.locator('[data-node-account-panel]').waitFor({state:'visible',timeout:remaining()});
 await idle();
 const perform=async(action,control)=>{remaining();const started=Date.now();onAction({action,phase:'started'});try{
  // click() waits for dispatch, not the async DOM event handler. Await its
  // public busy state before the next action, including refresh -> confirm.
  await control.click({timeout:remaining()});await idle();
  onAction({action,phase:'completed',elapsedMs:Date.now()-started});
 }catch(error){onAction({action,phase:'failed',elapsedMs:Date.now()-started});throw error;}};
 await perform('refresh',page.getByRole('button',{name:'Обновить PRIVATE запросы',exact:true}));
 const accept=page.getByRole('button',{name:'Подтвердить PRIVATE контакт',exact:true}).first();
 if(await accept.isVisible())await perform('confirm',accept);
}
module.exports={privatePairingStep};
