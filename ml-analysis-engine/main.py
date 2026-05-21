import os
import time
import json
import redis
import pika
import threading
import psutil
from fastapi import FastAPI, Response
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from sklearn.ensemble import IsolationForest

app = FastAPI()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

METRIC_TOTAL_LOGS = Counter('siem_processed_logs_total', 'Total network traffic logs processed', ['status'])
METRIC_ANOMALIES = Counter('siem_anomalies_detected_total', 'Total security attacks caught by ML model')
METRIC_BLOCKED_IPS = Gauge('siem_active_blocked_ips_count', 'Current number of blocked hacker IPs in Redis')
METRIC_CPU_USAGE = Gauge('infra_container_cpu_percent', 'Container runtime CPU capacity tracker')
METRIC_MEM_USAGE = Gauge('infra_container_memory_mb', 'Container memory utilization tracked in megabytes')

ml_model = IsolationForest(contamination=0.1, random_state=42)
ml_model.fit([[1, 1.0], [1, 2.0], [2, 0.5], [20, 0.01]])

def start_mq_consumer():
    rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")
    for _ in range(15):
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
            channel = connection.channel()
            channel.queue_declare(queue='telemetry_stream')
            break
        except pika.exceptions.AMQPConnectionError:
            time.sleep(2)
    else:
        raise RuntimeError("Broker mesh unavailable.")

    def log_processing_pipeline(ch, method, properties, body):
        payload = json.loads(body)
        ip = payload['ip']
        status = str(payload['status'])

        METRIC_TOTAL_LOGS.labels(status=status).inc()

        if r.exists(f"lockout:{ip}"):
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        r.lpush(f"window:{ip}", status)
        r.ltrim(f"window:{ip}", 0, 10)
        recent_statuses = r.lrange(f"window:{ip}", 0, -1)
        failures = sum(1 for item in recent_statuses if item == '401')

        prediction = ml_model.predict([[failures, 0.1]])

        if prediction[0] == -1 or failures >= 4:
            METRIC_ANOMALIES.inc()
            r.setex(f"lockout:{ip}", 60, "active")
            print(f"🚨 [SIEM ENGINE] Automated Blacklist Active for: {ip}")

        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue='telemetry_stream', on_message_callback=log_processing_pipeline)
    channel.start_consuming()

def monitor_system_resources():
    process = psutil.Process(os.getpid())
    while True:
        cpu = psutil.cpu_percent(interval=1.0)
        memory = process.memory_info().rss / (1024 * 1024)
        METRIC_CPU_USAGE.set(cpu)
        METRIC_MEM_USAGE.set(memory)
        time.sleep(1)

threading.Thread(target=start_mq_consumer, daemon=True).start()
threading.Thread(target=monitor_system_resources, daemon=True).start()

@app.get("/metrics")
def expose_prometheus_telemetry():
    METRIC_BLOCKED_IPS.set(len(r.keys("lockout:*")))
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)