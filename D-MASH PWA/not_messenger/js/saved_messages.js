// Local Account conversation. No Node or transport dependency.
(function (global) {
    'use strict';
    const ID = 'local:saved-messages:v1';
    const isLocal = id => id === ID;
    const peers = rows => [rows.find(row => isLocal(row.id)) || {id: ID, name: 'Избранное'}, ...rows.filter(row => !isLocal(row.id))];
    async function ensure(storage) {
        const alias = await storage.getAlias(ID, 'L1');
        if (!await storage.getBox('blind_peers', alias)) {
            await storage.putBox('blind_peers', {alias, data: {id: ID, name: 'Избранное'}});
        }
    }
    async function send(core, storage, content, control) {
        if (control || !core.activeIdentity || !storage.masterKey) return false;
        const input = global.document.getElementById('msgInput');
        const value = content || input?.value.trim();
        if (!value) return false;
        await ensure(storage);
        await storage.saveMessageGamma(ID, value, false, true, 'LOCAL');
        if (!content && input) {input.value = ''; input.style.height = '45px';}
        if (isLocal(core.activePeerId)) await core.selectPeer(ID);
        return true;
    }
    global.DmashSavedMessages = Object.freeze({ID, isLocal, peers, ensure, send});
})(typeof window === 'undefined' ? globalThis : window);
