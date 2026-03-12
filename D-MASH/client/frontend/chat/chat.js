let currentChatId = null;
let peersMap = {}; 
const myId = localStorage.getItem('my_id');

async function init() {
    if (!myId) {
        window.location.href = '/auth/login.html';
        return;
    }
    // Визуально показываем короткий, но сохраняем полный в памяти
    document.getElementById('my-id').innerText = `ID: ${myId.substring(0, 16)}... (Click to Copy)`;
    
    updateState();
    setInterval(updateState, 2000);
    setInterval(refreshMessages, 1000);
}

function sanitizeHTML(str) {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    localStorage.removeItem('my_id');
    window.location.href = '/auth/login.html';
}

async function updateState() {
    const resState = await fetch('/api/state').then(res => res.json()).catch(() => ({ peers: [] }));
    
    document.getElementById('statusBar').innerHTML = `
        <span>NEIGHBORS: ${resState.peers.length}</span>
        <span>ID: ${myId.substring(0,8)}</span>
        <span style="color:#0f0">TACT: ACTIVE</span>
    `;

    const resPeers = await fetch('/api/peers').then(res => res.json()).catch(() => []);
    
    const list = document.getElementById('peers');
    list.innerHTML = '';
    
    peersMap = {};
    resPeers.forEach(p => peersMap[p.user_id] = p);

    resPeers.forEach(p => {
        const div = document.createElement('div');
        div.className = 'peer-item';
        if (currentChatId === p.user_id) div.classList.add('active');
        
        const isOnline = resState.peers.includes(p.user_id);
        const statusColor = isOnline ? '#0f0' : '#555';
        const displayName = p.nickname ? p.nickname : p.user_id.substring(0, 8) + '...';
        
        const unreadCount = (p.user_id !== currentChatId && p.unread_count > 0) ? p.unread_count : 0;
        const unreadBadge = unreadCount > 0 
            ? `<span style="background:#e63946; color:#fff; border-radius:10px; padding:1px 6px; font-size:10px; font-weight:bold; margin-left:8px; line-height:14px; vertical-align:middle;">${unreadCount}</span>`
            : '';
        
        div.innerHTML = `
            <div>
                <div class="peer-name">${displayName} ${unreadBadge}</div>
                <div class.peer-id">${p.user_id.substring(0, 16)}</div>
            </div>
            <div style="width:8px; height:8px; border-radius:50%; background:${statusColor}" title="${isOnline ? 'Online' : 'Offline'}"></div>
        `;
        
        div.onclick = () => startChat(p.user_id);
        list.appendChild(div);
    });
    
    if (currentChatId) {
        const p = peersMap[currentChatId];
        const name = p && p.nickname ? p.nickname : (currentChatId.substring(0, 8) + '...');
        document.getElementById('chatTitle').innerText = `Chat with: ${name}`;
    }
}

async function startChat(targetId = null) {
    targetId = targetId || document.getElementById('targetId').value;
    if(!targetId) return;

    if (!peersMap[targetId]) {
        await fetch('/api/rename', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target_id: targetId, name: null})
        });
        await updateState();
    }
    
    currentChatId = targetId;
    document.getElementById('chatHeader').style.display = 'flex';
    document.getElementById('messages').innerHTML = '';
    
    await fetch('/api/read_chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({chat_id: currentChatId})
    });

    const peerItem = document.querySelector(`.peer-item .peer-id[innerText^='${targetId}']`);
    if(peerItem) {
        const badge = peerItem.closest('.peer-item').querySelector('.unread-badge');
        if(badge) badge.remove();
    }
    
    Array.from(document.querySelectorAll('.peer-item')).forEach(el => {
        el.classList.remove('active');
        const peerIdEl = el.querySelector('.peer-id');
        if (peerIdEl && peerIdEl.innerText.startsWith(targetId)) {
            el.classList.add('active');
        }
    });

    refreshMessages();
}

async function refreshMessages() {
    if(!currentChatId) return;

    const res = await fetch(`/api/messages/${currentChatId}`);
    if (!res.ok) return; // Добавлена проверка на случай ошибки сети
    const msgs = await res.json();
    
    const container = document.getElementById('messages');
    // Прокрутка к новым сообщениям будет работать лучше, если проверять до обновления
    const isAtBottom = container.scrollHeight - container.scrollTop <= container.clientHeight + 50;

    const newHtml = msgs.map(m => {
        const time = new Date(m.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        const isMe = m.is_outgoing;
        
        // --- ГЛАВНОЕ ИЗМЕНЕНИЕ ---
        // 1. Устанавливаем безопасное значение по умолчанию: отображение санитизированного текста.
        let contentHtml = sanitizeHTML(m.content);

        // 2. Пытаемся обработать как спец-протокол, ПЕРЕОПРЕДЕЛЯЯ contentHtml.
        try {
            // Проверяем, что это не пустая строка и начинается с '{'
            if (m.content && m.content.trim().startsWith('{')) {
                const json = JSON.parse(m.content);
                
                if (json.protocol === 'PCP') {
                    // Санитизируем только ту часть, что пришла от пользователя!
                    const sanitizedText = sanitizeHTML(json.text);
                    contentHtml = `
                        <div style="border: 1px solid #457b9d; background: #001d3d; padding: 10px; font-family: monospace; color: #4cc9f0;">
                            <div style="font-weight: bold; border-bottom: 1px solid #457b9d; margin-bottom: 5px;">📟 PHANTOM CALL</div>
                            <div>${sanitizedText}</div>
                            ${json.audio ? `<button onclick="playAudio('${json.audio}')" style="margin-top:5px; font-size:10px;">▶ PLAY NOISE</button>` : ''}
                        </div>
                    `;
                } else if (json.protocol === 'GVP') {
                    // Здесь нет пользовательского текста для санитизации, Salt - это hex, он безопасен.
                    contentHtml = `
                        <div style="border: 1px solid #e63946; background: #2b0505; padding: 10px;">
                            <div style="font-weight: bold; color: #e63946; margin-bottom: 5px;">🎙️ GHOST VOICE</div>
                            <div style="font-size: 10px; color: #aaa;">SALT: ${sanitizeHTML(json.salt.substring(0,16))}...</div>
                            <div style="display: flex; gap: 5px; margin-top: 5px;">
                                <button onclick="playAudio('${json.scrambled}')" style="background:#555; color:#fff; border:none; padding:5px;">🔊 NOISE</button>
                                <button onclick="playAudio('${json.restored}')" style="background:#e63946; color:#fff; border:none; padding:5px;">🔓 VOICE</button>
                            </div>
                        </div>
                    `;
                }
                // Если это какой-то другой JSON, мы его просто отобразим как санитизированный текст (поведение по умолчанию).
            }
        } catch(e) {
            // Если парсинг JSON не удался, значит это обычный текст.
            // contentHtml уже содержит безопасное значение, так что здесь ничего делать не нужно.
        }

        return `
            <div class="msg ${isMe ? 'me' : 'other'}">
                ${contentHtml}
                <div style="font-size: 9px; opacity: 0.5; text-align: right; margin-top: 3px;">${time}</div>
            </div>
        `;
    }).join('');

    // Обновляем DOM, только если есть реальные изменения.
    if (container.innerHTML !== newHtml) {
        container.innerHTML = newHtml;
        if (isAtBottom) {
            container.scrollTop = container.scrollHeight;
        }
    }
}

function showConnect() {
    document.getElementById('connectModal').style.display = 'flex';
}

async function connectNode() {
    const addr = document.getElementById('nodeAddress').value;
    await fetch('/api/connect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({address: addr})
    });
    document.getElementById('connectModal').style.display = 'none';
}

function showRename() {
    if (!currentChatId) return;
    document.getElementById('renameModal').style.display = 'flex';
    document.getElementById('newName').value = '';
    document.getElementById('newName').focus();
}

async function submitRename() {
    const name = document.getElementById('newName').value;
    if (!name || !currentChatId) return;
    
    await fetch('/api/rename', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target_id: currentChatId, name: name})
    });
    
    document.getElementById('renameModal').style.display = 'none';
    updateState();
}

async function send() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    
    if (mode === 'GVP') {
        const fileInput = document.getElementById('fileInput');
        if (fileInput.files.length === 0) return alert("Select audio file!");
        
        const file = fileInput.files[0];
        const reader = new FileReader();
        reader.onload = async function(e) {
            const base64Data = e.target.result; // "data:audio/wav;base64,..."
            
            await fetch('/api/send', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    target_id: currentChatId, 
                    text: "", 
                    msg_type: "GVP",
                    file_data: base64Data
                })
            });
            fileInput.value = '';
            refreshMessages();
        };
        reader.readAsDataURL(file);
        
    } else {
        const txt = document.getElementById('msgInput').value;
        if(!txt || !currentChatId) return;
        
        await fetch('/api/send', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                target_id: currentChatId, 
                text: txt,
                msg_type: mode // TEXT or PCP
            })
        });
        document.getElementById('msgInput').value = '';
        refreshMessages();
    }
}
// Вспомогательная функция для воспроизведения Base64 аудио
function playAudio(b64) {
    const audio = new Audio("data:audio/wav;base64," + b64);
    audio.play();
}
// ДОБАВЬ ЭТУ ФУНКЦИЮ В КОНЕЦ
function copyId() {
    if (!myId) return;
    navigator.clipboard.writeText(myId).then(() => {
        const el = document.getElementById('my-id');
        const originalText = el.innerText;
        el.innerText = "COPIED TO CLIPBOARD!";
        el.style.color = "#0f0";
        
        setTimeout(() => {
            el.innerText = `ID: ${myId.substring(0, 16)}... (Click to Copy)`;
            el.style.color = "#666";
        }, 1500);
    }).catch(err => {
        console.error('Failed to copy: ', err);
        // Если не сработало (например, нет HTTPS), покажем полный ID чтобы скопировать руками
        prompt("Copy your full ID:", myId);
    });
}

function toggleMode() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const txtInput = document.getElementById('msgInput');
    const fileInput = document.getElementById('fileInput');
    const btn = document.getElementById('sendBtn');

    if (mode === 'GVP') {
        txtInput.style.display = 'none';
        fileInput.style.display = 'block';
        btn.innerText = 'ENCRYPT & SEND';
        btn.style.background = '#e63946'; // Red for Ghost
    } else if (mode === 'PCP') {
        txtInput.style.display = 'block';
        fileInput.style.display = 'none';
        txtInput.placeholder = "Enter text for Phantom Call...";
        btn.innerText = 'TRANSMIT';
        btn.style.background = '#457b9d'; // Blue for Phantom
    } else {
        txtInput.style.display = 'block';
        fileInput.style.display = 'none';
        txtInput.placeholder = "Type encrypted message...";
        btn.innerText = 'SEND';
        btn.style.background = '#0f0';
    }
}

init();
