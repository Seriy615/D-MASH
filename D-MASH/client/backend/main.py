import uvicorn
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Импортируем обновленный lifespan из core (где происходит PoW и инициализация БД)
from core import lifespan
from api import router

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

# 3. Статика (Frontend)
frontend_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
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

    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=False,
        ssl_keyfile=ssl_key, 
        ssl_certfile=ssl_cert
    )

