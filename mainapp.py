from flask import Flask, render_template, jsonify, request
import threading
import time
from datetime import datetime
import pickle
import numpy as np
import psutil
import random

app = Flask(__name__)

# Load your trained XGBoost model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# Load encoders if proto and service are label-encoded
with open("proto_encoder.pkl", "rb") as f:
    proto_encoder = pickle.load(f)

# Refitting the service encoder with the possible services
try:
    with open("service_encoder.pkl", "rb") as f:
        service_encoder = pickle.load(f)
except FileNotFoundError:
    from sklearn.preprocessing import LabelEncoder
    service_encoder = LabelEncoder()
    service_encoder.fit(['http', 'mqtt', 'ftp', 'ssh', 'smtp', 'dns', 'https', 'telnet', 'pop3'])
    with open("service_encoder.pkl", "wb") as f:
        pickle.dump(service_encoder, f)

# Attack class labels in the same order used during model training
attack_classes = [
    'Wipro_bulb',
    'NMAP_UDP_SCAN',
    'MQTT_Publish',
    'ARP_poisioning',
    'NMAP_OS_DETECTION',
    'NMAP_TCP_scan',
    'Metasploit_Brute_Force_SSH',
    'NMAP_FIN_SCAN',
    'Thing_Speak',
    'NMAP_XMAS_TREE_SCAN',
    'DDOS_Slowloris',
    'DOS_SYN_Hping'
]

# Store live metrics and logs
system_stats = []
attack_logs = []

# Background thread to simulate packet sniffing and attack detection
def packet_sniffer():
    while True:
        proto = random.choice(['tcp', 'udp', 'icmp'])
        service = random.choice(['http', 'mqtt', 'ftp', 'ssh', 'smtp'])

        data_point = {
            'proto': proto,
            'service': service,
            'fwd_URG_flag_count': random.randint(0, 2),
            'fwd_pkts_payload.min': random.uniform(0, 100),
            'fwd_pkts_payload.avg': random.uniform(0, 100),
            'fwd_iat.max': random.uniform(0, 1000),
            'idle.min': random.uniform(0, 500),
            'idle.avg': random.uniform(0, 500),
            'fwd_init_window_size': random.randint(0, 65535),
            'fwd_last_window_size': random.randint(0, 65535)
        }

        try:
            proto_encoded = proto_encoder.transform([data_point['proto']])[0]
        except:
            proto_encoded = -1

        try:
            service_encoded = service_encoder.transform([data_point['service']])[0]
        except:
            service_encoded = -1

        features = np.array([
            proto_encoded,
            service_encoded,
            data_point['fwd_URG_flag_count'],
            data_point['fwd_pkts_payload.min'],
            data_point['fwd_pkts_payload.avg'],
            data_point['fwd_iat.max'],
            data_point['idle.min'],
            data_point['idle.avg'],
            data_point['fwd_init_window_size'],
            data_point['fwd_last_window_size']
        ]).reshape(1, -1)

        prediction = model.predict(features)[0]
        attack_type = attack_classes[int(prediction)]

        log_entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack": attack_type,
            "source": "Simulated Sniffer"
        }
        attack_logs.append(log_entry)

        if len(attack_logs) > 100:
            attack_logs.pop(0)

        time.sleep(2)

# Background thread to collect system performance metrics
def system_monitor():
    while True:
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        latency = random.uniform(0, 150)

        stats = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "cpu": cpu,
            "mem": mem,
            "latency": latency
        }
        system_stats.append(stats)

        if len(system_stats) > 60:
            system_stats.pop(0)

        time.sleep(2)

# Endpoint to receive attacks from attacker Pi
@app.route('/api/simulate', methods=['POST'])
def simulate_attack():
    data = request.get_json()

    try:
        proto_encoded = proto_encoder.transform([data['proto']])[0]
    except:
        proto_encoded = -1

    try:
        service_encoded = service_encoder.transform([data['service']])[0]
    except:
        service_encoded = -1

    features = np.array([
        proto_encoded,
        service_encoded,
        data['fwd_URG_flag_count'],
        data['fwd_pkts_payload.min'],
        data['fwd_pkts_payload.avg'],
        data['fwd_iat.max'],
        data['idle.min'],
        data['idle.avg'],
        data['fwd_init_window_size'],
        data['fwd_last_window_size']
    ]).reshape(1, -1)

    prediction = model.predict(features)[0]
    attack_type = attack_classes[int(prediction)]

    log_entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack": attack_type,
        "source": "Attacker Pi"
    }
    attack_logs.append(log_entry)
    if len(attack_logs) > 100:
        attack_logs.pop(0)

    return jsonify({"status": "received", "predicted_attack": attack_type}), 200

# Dashboard routes
@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/api/metrics')
def metrics():
    return jsonify(system_stats)

@app.route('/api/logs')
def logs():
    return jsonify(attack_logs)

if __name__ == '__main__':
    threading.Thread(target=packet_sniffer, daemon=True).start()
    threading.Thread(target=system_monitor, daemon=True).start()
    app.run(debug=True, host='0.0.0.0', port=5000)

