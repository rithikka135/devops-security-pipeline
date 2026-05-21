import os
import time
import json
import random
import pika

IPS_POOL = ["192.168.4.55", "10.1.12.4", "172.19.88.2", "185.220.101.5"]
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")

for _ in range(15):
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue='telemetry_stream')
        break
    except pika.exceptions.AMQPConnectionError:
        time.sleep(2)
else:
    raise RuntimeError("Log generator engine failed to lock connection to message broker.")

print("🚀 Network log stream simulations running...")

while True:
    selected_ip = random.choice(IPS_POOL)
    
    if selected_ip == "185.220.101.5":
        status_code = 401
        req = "POST /api/v1/auth/login"
    else:
        status_code = random.choice([200, 200, 200, 401])
        req = "GET /index.html" if status_code == 200 else "POST /api/v1/auth/login"

    log_packet = {
        "ip": selected_ip,
        "timestamp": time.time(),
        "request_type": req,
        "status": status_code
    }

    channel.basic_publish(exchange='', routing_key='telemetry_stream', body=json.dumps(log_packet))
    print(f"✨ Transmitted Packet Payload: {selected_ip} -> {status_code}")
    
    time.sleep(random.uniform(0.1, 0.4) if selected_ip == "185.220.101.5" else random.uniform(0.3, 1.2))