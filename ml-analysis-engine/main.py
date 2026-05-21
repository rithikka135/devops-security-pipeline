import os
import time
import json
import redis
import pika
import threading
from fastapi import FastAPI, Response
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from sklearn.ensemble import IsolationForest

app = FastAPI()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

METRIC_TOTAL_LOGS = Counter('siem_processed_logs_total', 'Total network traffic logs processed', ['status'])
METRIC_ANOMALIES = Counter('siem_anomalies_detected_total', 'Total security attacks caught by ML model')
METRIC_BLOCKED_IPS = Gauge('siem_active_blocked_ips_count', 'Current number of blocked hacker IPs in Redis')

ml_model = IsolationForest(contamination=0.1, random_state=42)
ml_model.fit([[1, 1.0], [1, 2.0], [2, 0.5], [20, 0.01]])

def start_mq_consumer():
    rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")
    
    for i in range(15):
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
            channel = connection.channel()
            channel.queue_declare(queue='telemetry_stream')
            break
        except pika.exceptions.AMQPConnectionError:
            time.sleep(2)
    else:
        raise RuntimeError("Failed to attach to RabbitMQ Broker mesh infrastructure.")

    def log_processing_pipeline(ch, method, properties, body):
        payload = json.loads(body)
        ip = payload['ip']
        status = str(payload['status'])

        METRIC_TOTAL_LOGS.labels(status=status).inc()

        if r.exists(f"lockout:{ip}"):
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        r.lpush(f"window:{ip}", payload['status'])
        r.ltrim(f"window:{ip}", 0, 10)
        recent_statuses = r.lrange(f"window:{ip}", 0, -1)
        failures = sum(1 for item in recent_statuses if item == '401')

        prediction = ml_model.predict([[failures, 0.1]])

        if prediction[0] == -1 or failures >= 4:
            METRIC_ANOMALIES.inc()
            r.setex(f"lockout:{ip}", 60, "active")  # Block malicious actor for 60 seconds
            print(f"🚨 [SIEM OUTLIER DETECTED] Malicious threat signature from IP: {ip}. Blacklist applied.")

        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue='telemetry_stream', on_message_callback=log_processing_pipeline)
    channel.start_consuming()

threading.Thread(target=start_mq_consumer, daemon=True).start()

@app.get("/metrics")
def expose_prometheus_telemetry():
    active_bans = len(r.keys("lockout:*"))
    METRIC_BLOCKED_IPS.set(active_bans)
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)