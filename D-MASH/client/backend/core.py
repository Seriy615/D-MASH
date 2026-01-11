
import os
from contextlib import asynccontextmanager
from typing import Optional, Set
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from database import DatabaseManager
from network import P2PNode
from tact import TactEngine
from crypto import CryptoManager, NodeCryptoManager

# --- D-MASH CONFIGURATION ---
TACT_INTERVAL = 1.5
PACKET_SIZE = 4096
P2P_PORT = int(os.getenv("P2P_PORT", 9000))
NODE_KEY_FILE = "node_identity.key" # Файл для хранения ключа ноды

class AppState:
    node: Optional[P2PNode] = None
    tact: Optional[TactEngine] = None
    
    system_db: Optional[DatabaseManager] = None # База демона
    db: Optional[DatabaseManager] = None        # База юзера
    
    crypto: Optional[CryptoManager] = None      # Криптография юзера
    node_crypto: Optional[NodeCryptoManager] = None # Криптография ноды (Identity)
    
    user_id: str = ""
    is_logged_in: bool = False
    background_tasks: Set[asyncio.Task] = set()

state = AppState()

def ensure_node_identity():
    """
    Загружает или генерирует (с майнингом) Identity ноды.
    Возвращает hex приватного ключа подписи.
    """
    if os.path.exists(NODE_KEY_FILE):
        print(f"🔑 [CORE] Loading existing Node Identity from {NODE_KEY_FILE}")
        with open(NODE_KEY_FILE, "r") as f:
            return f.read().strip()
    else:
        print(f"⚠️ [CORE] Node Identity not found. Starting initialization...")
        # Майнинг PoW (может занять время)
        signing_key_hex, node_id = NodeCryptoManager.generate_node_identity()
        
        with open(NODE_KEY_FILE, "w") as f:
            f.write(signing_key_hex)
        
        print(f"✅ [CORE] New Identity generated: {node_id}")
        print(f"💾 [CORE] Saved to {NODE_KEY_FILE}")
        return signing_key_hex

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Инициализация Identity Ноды (Синхронно, блокирует старт до завершения PoW)
    node_signing_key = ensure_node_identity()
    state.node_crypto = NodeCryptoManager(node_signing_key)
    print(f"🌐 [CORE] Node ID: {state.node_crypto.node_id}")

    # 2. Запускаем Системную БД
    # Используем system.db вместо bootstrap_peers.db для новой архитектуры
    state.system_db = DatabaseManager("system.db")
    
    # ВАЖНО: Подключаем криптографию ноды к БД для работы Blind Storage
    state.system_db.set_node_crypto(state.node_crypto)
    
    await state.system_db.connect()

    # 3. Запускаем Демона
    state.node = P2PNode(state.system_db) 
    
    # 4. Запускаем Tact Engine
    state.tact = TactEngine(state.system_db, state.node, TACT_INTERVAL, PACKET_SIZE)
    
    t1 = asyncio.create_task(state.node.start_server(P2P_PORT))
    t2 = asyncio.create_task(state.tact.start())
    state.background_tasks.update([t1, t2])
    t1.add_done_callback(state.background_tasks.discard)
    t2.add_done_callback(state.background_tasks.discard)
    
    yield
    
    print("🛑 [CORE] Shutting down...")
    for task in state.background_tasks: task.cancel()
    if state.db: await state.db.close()
    if state.system_db: await state.system_db.close()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from api import router as api_router
app.include_router(api_router)

frontend_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
