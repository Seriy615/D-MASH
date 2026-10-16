'use strict';
// Actual panel/action handlers with an asynchronous adapter and minimal DOM.
// No browser, network, authentication or readiness acceptance is implied.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../js/node_account_ui_v4.js'), 'utf8');
const deferred = () => {let resolve, reject; const promise = new Promise((yes, no) => {resolve = yes; reject = no;}); return {promise, resolve, reject};};
const settle = async () => {for (let i = 0; i < 12; i++) await Promise.resolve();};
class Element {
    constructor(tag, document) {this.tag = tag; this.ownerDocument = document; this.children = []; this.attributes = {}; this.listeners = {}; this.dataset = {}; this.disabled = false; this.textContent = ''; this.value = '';}
    append(...children) {this.children.push(...children);}
    replaceChildren(...children) {this.children = children;}
    setAttribute(name, value) {this.attributes[name] = value;}
    addEventListener(name, action) {this.listeners[name] = action;}
    querySelectorAll(selector) {assert.equal(selector, 'button'); return this.children.flatMap(child => [...(child.tag === 'button' ? [child] : []), ...child.querySelectorAll(selector)]);}
    querySelector() {return null;}
}
function fixture() {
    const document = {createElement(tag) {return new Element(tag, this);},
        querySelector(selector) {if (selector === '[data-node-account-panel]') return this.panel; if (selector === '[data-node-account-close]') return this.close; return null;}};
    let mounted, closed = 0, offers = async () => [], routes = async () => [];
    const adapter = {privateOffers: () => offers()};
    const host = {publicRoutes: () => routes()};
    const core = {keys: {sign: {}}, openModal() {document.panel = document.createElement('div'); document.close = document.createElement('button');}, closeModal() {}, async openPublicAccountNodeV4() {return adapter;}};
    const context = {document, DMASH_NODE_PROFILE: 'managed-v4', DeviceRoot: {},
        DmashManagedNodeCatalogV4: {mount(container, options) {mounted = options; return {close() {closed++;}};}},
        setInterval() {return 1;}, clearInterval() {}, crypto, navigator: {clipboard: {async writeText() {}}}};
    vm.runInNewContext(source, context);
    const open = () => {context.DmashNodeAccountUiV4.open(core); return document.panel;};
    open();
    const status = panel => panel.children[0];
    const button = (panel, label) => {const result = panel.querySelectorAll('button').find(node => node.textContent === label); assert(result, 'Actual button must exist: ' + label); return result;};
    return {document, core, adapter, host, open, status, button,
        async ready() {await mounted.onReady({host, coordinator: {}});},
        offers(fn) {offers = fn;}, routes(fn) {routes = fn;}, close() {document.close.listeners.click();}, get closed() {return closed;}};
}
(async () => {
    const f = fixture(); await f.ready(); const panel = f.document.panel;
    const refresh = f.button(panel, 'Обновить PRIVATE запросы');
    const disabledBefore = f.button(panel, 'Копировать PRIVATE адрес'); disabledBefore.disabled = true;
    const gate = deferred(); f.offers(() => gate.promise);
    const pending = refresh.listeners.click(); await settle();
    assert.equal(panel.attributes['aria-busy'], 'true'); assert.equal(f.status(panel).textContent, 'Выполняется…');
    assert(panel.querySelectorAll('button').every(node => node.disabled));
    await f.button(panel, 'Копировать публичный адрес').listeners.click();
    assert.equal(f.status(panel).textContent, 'Выполняется…', 'Repeated actions cannot run while one is busy');
    gate.resolve([]); await pending;
    assert.equal(f.status(panel).textContent, 'Действие завершено', 'Successful refresh must not leave the panel loading');
    assert.equal(panel.attributes['aria-busy'], 'false'); assert(refresh.disabled === false && disabledBefore.disabled === true);

    const publicGate = deferred(); f.routes(() => publicGate.promise);
    const publicRefresh = f.button(panel, 'Обновить запросы').listeners.click(); await settle();
    assert.equal(panel.attributes['aria-busy'], 'true'); publicGate.resolve([]); await publicRefresh;
    assert.equal(f.status(panel).textContent, 'Действие завершено');

    // Status supplied by an action or an asynchronous status observer wins over
    // the neutral completion message: pending/keys are separate protocol facts.
    for (const explicit of ['Ожидание подтверждения второго участника', 'Ключи подтверждены', 'Подключение недоступно']) {
        const gate = deferred(); f.offers(async () => {await gate.promise; f.status(panel).textContent = explicit; return [];});
        const action = refresh.listeners.click(); await settle(); gate.resolve(); await action;
        assert.equal(f.status(panel).textContent, explicit); assert.equal(panel.attributes['aria-busy'], 'false');
    }
    for (const code of ['NODE_UNAVAILABLE', 'ACCOUNT_SESSION_CHANGED']) {
        const failure = deferred(); f.offers(() => failure.promise);
        const failed = refresh.listeners.click(); await settle(); failure.reject(Object.assign(Error('unavailable'), {code})); await failed;
        assert.equal(f.status(panel).textContent, code); assert.equal(panel.attributes['aria-busy'], 'false'); assert.equal(refresh.disabled, false);
    }

    // Exercise the actual pending-confirmation path, rather than equating a
    // completed click with a ready contact or confirmed cryptographic keys.
    f.offers(async () => [{id: 'offer', pending: false, requests: [{direction: 'OUTBOUND', targetBundle: JSON.stringify({account_keys: {signing: 'a'.repeat(64)}}), state: 'PENDING', exchangeId: 'exchange', requestDigest: 'digest'}]}]);
    f.adapter.advancePrivate = async () => ({ready: false});
    await refresh.listeners.click();
    await f.button(panel, 'Подтвердить PRIVATE контакт').listeners.click();
    assert.equal(f.status(panel).textContent, 'Ожидание подтверждения второго участника');

    const late = deferred(); f.offers(() => late.promise); const old = refresh.listeners.click(); await settle();
    f.close(); const replacement = f.open();
    assert.equal(f.closed, 1, 'Close and replacement retire the prior panel catalog idempotently');
    late.resolve([]); await old;
    assert.equal(f.status(replacement).textContent, 'Подключите Node, чтобы открыть публичные запросы.', 'Late old completion cannot overwrite replacement panel');
    assert(replacement.querySelectorAll('button').every(node => !node.disabled));
    console.log('PASS actual Node panel async actions: loading during work, neutral success, explicit pending/keys/error preserved, captured disabled states restored, repeated action blocked and closed/replaced view isolated');
})().catch(error => {console.error(error); process.exitCode = 1;});
