import uvicorn
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Импортируем обновленный lifespan из core (где происходит PoW и инициализация БД)
from core import lifespan
from api import router
from client_gateway import router as client_gateway_router

# --- СОЗДАЕМ ПРИЛОЖЕНИЕ ---
app = FastAPI(lifespan=lifespan)

# 1. Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. API Роуты
app.include_router(router)
app.include_router(client_gateway_router)

# 3. Статика (Frontend)
backend_path = os.path.dirname(os.path.abspath(__file__))
# Canonical checkout: ``client/frontend``. Docker/Compose: ``backend/frontend``.
# Prefer a present mount so either supported runtime layout starts correctly.
frontend_candidates = (
    os.path.join(backend_path, "frontend"),
    os.path.join(os.path.dirname(backend_path), "frontend"),
)
frontend_path = next((path for path in frontend_candidates if os.path.isdir(path)), frontend_candidates[-1])
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
else:
    print("⚠️ [MAIN] Frontend directory not found. Web UI might not work.")

# --- ТОЧКА ВХОДА ---
if __name__ == "__main__":
    # Проверка наличия сертификатов (чтобы не падать при локальном запуске без Docker)
    ssl_key = "/app/certs/key.pem"
    ssl_cert = "/app/certs/cert.pem"
    
    use_ssl = os.path.exists(ssl_key) and os.path.exists(ssl_cert)
    
    if use_ssl:
        print(f"🔒 [MAIN] Starting with SSL ({ssl_cert})")
    else:
        print("⚠️ [MAIN] SSL certs not found. Starting in HTTP mode (insecure).")
        ssl_key = None
        ssl_cert = None

    host = os.getenv("DMASH_HTTP_HOST", "0.0.0.0")
    port = int(os.getenv("DMASH_HTTP_PORT", "8000"))

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=False,
        ssl_keyfile=ssl_key, 
        ssl_certfile=ssl_cert
    )

