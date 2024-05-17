import asyncio
import websockets

async def send_and_receive_message():
    async with websockets.connect('ws://10.10.2.147:8765') as websocket:
        message = input("Enter message to send: ")
        await websocket.send(message)
        print(f"Message sent: {message}")

        # Ожидание ответа от сервера
        response = await websocket.recv()
        print(f"Response from server: {response}")

asyncio.run(send_and_receive_message())
