import json
import websocket


ws = websocket.create_connection(
    "ws://127.0.0.1:8000/ws/telemetry"
)

print("Connected to AEGIS WebSocket")

while True:

    message = ws.recv()

    data = json.loads(message)

    print("\nReceived telemetry:")
    print(json.dumps(data, indent=2))
