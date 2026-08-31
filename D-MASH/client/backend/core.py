
import os
from contextlib import asynccontextmanager
from typing import Optional, Set
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor

from database import DatabaseManager
from network import P2PNode
from tact import TactEngine
from crypto import CryptoManager, NodeCryptoManager
from notification import NotificationTrigger, OriginNotificationClient
try:  # Runtime scripts import backend modules as top-level modules.
    from capabilities import NodeCapabilities
except ModuleNotFoundError:  # Package tests import ``backend.core``.
    from .capabilities import NodeCapabilities

# --- D-MASH CONFIGURATION ---
TACT_INTERVAL = 1.5
PACKET_SIZE = 4096
P2P_PORT = int(os.getenv("P2P_PORT", 9000))
P2P_HOST = os.getenv("P2P_HOST", "0.0.0.0")
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

    process_pool: Optional[Executor] = None
    capabilities: Optional[NodeCapabilities] = None

state = AppState()


async def maintain_mesh_peers() -> None:
    """Reconnect known dialable mesh peers without involving PWA identities."""
    while True:
        try:
            for peer in await state.system_db.get_all_neighbors():
                peer_id = peer.get("real_node_id")
                address = peer.get("address")
                if not peer_id or not isinstance(address, str) or address == "incoming" or ":" not in address:
                    continue
                if peer_id not in state.node.active_connections:
                    await state.node.connect_to(address)
        except Exception:
            # Neighbor addresses are node-local encrypted state. Keep retrying
            # without logging a social graph or a raw routing locator.
            pass
        await asyncio.sleep(10)


def create_crypto_executor() -> Executor:
    """Prefer process isolation, with an explicit/automatic hosting fallback."""
    mode = os.getenv("DMASH_EXECUTOR", "auto").lower()
    if mode not in {"auto", "process", "thread"}:
        raise ValueError("DMASH_EXECUTOR must be auto, process, or thread")
    if mode == "thread":
        return ThreadPoolExecutor(max_workers=2, thread_name_prefix="dmash-crypto")
    try:
        return ProcessPoolExecutor(max_workers=2)
    except OSError:
        if mode == "process":
            raise
        print("⚠️ [CORE] Process executor unavailable; using thread fallback.")
        return ThreadPoolExecutor(max_workers=2, thread_name_prefix="dmash-crypto")

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
    state.capabilities = NodeCapabilities.from_env()
    print(f"🌐 [CORE] Node ID: {state.node_crypto.node_id}")
    state.process_pool = create_crypto_executor()
    # 2. Запускаем Системную БД
    # Используем system.db вместо bootstrap_peers.db для новой архитектуры
    state.system_db = DatabaseManager("system.db")
    
    # ВАЖНО: Подключаем криптографию ноды к БД для работы Blind Storage
    state.system_db.set_node_crypto(state.node_crypto)
    origin_client = OriginNotificationClient.from_env()
    if origin_client:
        state.system_db.set_notification_trigger(NotificationTrigger(origin_client.send))
    
    await state.system_db.connect()
    await state.system_db.rehydrate_notifications()

    # 3. Запускаем Демона
    state.node = P2PNode(
        state.system_db,
        can_route=state.capabilities.can_route,
        can_accept_devices=state.capabilities.can_accept_devices,
    )
    
    # 4. Запускаем Tact Engine
    state.tact = TactEngine(state.system_db, state.node, TACT_INTERVAL, PACKET_SIZE)
    
    t1 = asyncio.create_task(state.node.start_server(P2P_PORT, P2P_HOST))
    t2 = asyncio.create_task(state.tact.start())
    t3 = asyncio.create_task(maintain_mesh_peers())
    state.background_tasks.update([t1, t2, t3])
    t1.add_done_callback(state.background_tasks.discard)
    t2.add_done_callback(state.background_tasks.discard)
    
    yield
    
    print("🛑 [CORE] Shutting down...")
    for task in state.background_tasks: task.cancel()
    state.process_pool.shutdown(wait=False) # <--- НЕ ЗАБУДЬТЕ ЗАКРЫТЬ
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
from client_gateway import router as client_gateway_router
app.include_router(client_gateway_router)

backend_path = os.path.dirname(os.path.abspath(__file__))
# Canonical checkout: ``client/frontend``. Docker/Compose: ``backend/frontend``.
# Prefer a present mount so either supported runtime layout starts correctly.
frontend_candidates = (
    os.path.join(backend_path, "frontend"),
    os.path.join(os.path.dirname(backend_path), "frontend"),
)
frontend_path = next((path for path in frontend_candidates if os.path.isdir(path)), frontend_candidates[-1])
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
