import asyncio
import websockets

async def handle_client(websocket, path):
    async for message in websocket:
        print(f"Received message from client: {message}")
        # Преобразование сообщения в верхний регистр
        uppercase_message = message.upper()
        print(f"Sending back to client: {uppercase_message}")
        # Отправка обратно клиенту
        await websocket.send(uppercase_message)

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 8765):
        print("WebSocket server started...")
        await asyncio.Future()  # Бесконечное ожидание

if __name__ == "__main__":
    asyncio.run(main())
