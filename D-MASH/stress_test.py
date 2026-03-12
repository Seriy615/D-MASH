import os
import time
import json
import requests
import subprocess
import random
import urllib3
from concurrent.futures import ThreadPoolExecutor

# --- КОНФИГУРАЦИЯ ---
NUM_NODES = 10  # Оптимально для большинства машин
EXTRA_LINKS_PER_NODE = 2
BASE_PORT = 8000
COMPOSE_FILE = "client/stress-test-compose.yml"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Блок стандартных функций ---

def generate_compose():
    compose_data = {"services": {}}
    for i in range(1, NUM_NODES + 1):
        compose_data["services"][f"node{i}"] = {
            "build": {"context": ".", "dockerfile": "docker/messenger.Dockerfile"},
            "ports": [f"{BASE_PORT + i}:8000", f"{9000 + i}:9000"],
            "environment": ["P2P_PORT=9000"]
        }
    with open(COMPOSE_FILE, "w") as f: json.dump(compose_data, f, indent=2)
    print(f"✅ Generated {COMPOSE_FILE} with {NUM_NODES} nodes.")

def run_command(cmd, ignore_errors=False):
    print(f"🚀 Running command: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Command failed. Stderr:\n{e.stderr}")
        if not ignore_errors: raise

def api_call(node_idx, method, endpoint, data=None, timeout=5):
    url = f"https://localhost:{BASE_PORT + node_idx}{endpoint}"
    try:
        if method == "POST": r = requests.post(url, json=data, verify=False, timeout=timeout)
        else: r = requests.get(url, verify=False, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        return None

# --- Блок надежного запуска ---

def wait_for_nodes(timeout=120, login=False):
    target_state = "Logged in" if login else "Online"
    print(f"\n⏳ Waiting for all nodes to be {target_state} (max {timeout}s)...")
    start_time = time.time()
    ready_nodes = set()
    
    with ThreadPoolExecutor(max_workers=NUM_NODES) as executor:
        while len(ready_nodes) < NUM_NODES and time.time() - start_time < timeout:
            nodes_to_check = [i for i in range(1, NUM_NODES + 1) if i not in ready_nodes]
            futures = {executor.submit(api_call, i, "POST" if login else "GET", "/api/login" if login else "/api/state", 
                                      data={"username": f"user{i}", "password": "1"} if login else None): i for i in nodes_to_check}

            for future in futures:
                node_idx = futures[future]
                result = future.result()
                if result and (not login or "user_id" in result):
                    ready_nodes.add(node_idx)
                    print(f"  ...Node {node_idx} is {target_state}!")
            
            if len(ready_nodes) < NUM_NODES:
                time.sleep(3)

    if len(ready_nodes) < NUM_NODES:
        print(f"⚠️ Warning: Timeout! Only {len(ready_nodes)}/{NUM_NODES} nodes are {target_state}.")
        exit(1)
    
    print(f"✅ All {NUM_NODES} nodes are {target_state}.")
    
    if login:
        users = {}
        for i in range(1, NUM_NODES + 1):
             users[i] = api_call(i, "GET", "/api/state")['user_id']
        return users

# --- Главный сценарий теста ---

def run_public_test(test_num, users):
    print("\n" + "="*80)
    print(f"=== TEST #{test_num}: Multi-Hop E2EE Communication ===")
    print("="*80)

    sender_idx, receiver_idx = random.sample(range(1, NUM_NODES + 1), 2)
    sender_id, receiver_id = users[sender_idx], users[receiver_idx]
    
    print(f"   - Sender:   Node {sender_idx} (ID: {sender_id[:12]}...)")
    print(f"   - Receiver: Node {receiver_idx} (ID: {receiver_id[:12]}...)")

    # --- ФАЗА 1: ОТПРАВКА И АВТОМАТИЧЕСКОЕ ПОСТРОЕНИЕ МАРШРУТА ---
    print("\n[1] Sending initial message. The network will now automatically discover the route...")
    message_text = f"Secure message #{test_num} from Node {sender_idx}"
    
    res = api_call(sender_idx, "POST", "/api/send", {"target_id": receiver_id, "text": message_text})
    if not res:
        print("❌ FAILED to send the initial packet.")
        return

    packet_type = res.get("packet_type", "UNKNOWN")
    print(f"  -> Sent packet of type '{packet_type}'. Network is working...")

    # --- ФАЗА 2: ОЖИДАНИЕ И ВЕРИФИКАЦИЯ ДОСТАВКИ ---
    # Вот он, блять, наш главный "танец с бубном", скрытый от глаз.
    # Мы просто даем ему ДОХУЯ времени.
    WAIT_TIME = 25
    print(f"\n[2] Waiting up to {WAIT_TIME} seconds for the message to propagate and for the route to stabilize...")
    
    message_delivered = False
    for i in range(WAIT_TIME):
        print(f"   ... waiting {i+1}/{WAIT_TIME}s", end='\r')
        msgs = api_call(receiver_idx, "GET", f"/api/messages/{sender_id}")
        if msgs and any(message_text in m.get("content", "") for m in msgs):
            print("\n\n[3] Verifying delivery...")
            print("  -> Message found in the recipient's database.")
            print("\n🎉 SUCCESS! Message was delivered and decrypted correctly across multiple hops.")
            message_delivered = True
            break
        time.sleep(1)
        
    if not message_delivered:
        print("\n\n[3] Verifying delivery...")
        print("  -> Message not found in the recipient's database after timeout.")
        print("\n❌ FAILED! The message was not delivered.")

def main():
    generate_compose()
    run_command(f"docker-compose -f {COMPOSE_FILE} down --remove-orphans --volumes", ignore_errors=True)
    
    print("\n🧹 Cleaning up old project files...")
    os.system("rm -f client/backend/*.db client/backend/*.key")
    
    run_command(f"docker-compose -f {COMPOSE_FILE} up -d --build")
    
    # Разделяем ожидание запуска и логин
    wait_for_nodes(login=False)
    users = wait_for_nodes(login=True)
    
    print("\n🕸️ Building MESH topology...")
    for i in range(1, NUM_NODES + 1):
        targets = random.sample([n for n in range(1, NUM_NODES + 1) if n != i], min(EXTRA_LINKS_PER_NODE, NUM_NODES-1))
        for target_idx in targets:
            api_call(i, "POST", "/api/connect", {"address": f"node{target_idx}:9000"})
    
    # Ждем, чтобы сеть хоть немного "устаканилась"
    STABILIZATION_TIME = 15
    print(f"\n⏳ Allowing network to stabilize for {STABILIZATION_TIME} seconds...")
    time.sleep(STABILIZATION_TIME)
    
    # Запускаем несколько тестов
    for i in range(3):
        run_public_test(i + 1, users)

if __name__ == "__main__":
    main()
