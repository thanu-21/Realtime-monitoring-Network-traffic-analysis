import time
import pandas as pd
import numpy as np
import mysql.connector
import joblib
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import RandomForestClassifier

# Database Configuration
db_config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'network_traffic'
}

# Load Pre-trained Model
model = joblib.load('ml_model.joblib')

# Create table if not exists
def create_table():
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS network (
            id INT AUTO_INCREMENT PRIMARY KEY,
            src_ip VARCHAR(255),
            dst_ip VARCHAR(255),
            src_port INT,
            dst_port INT,
            protocol INT,
            packet_length INT,
            ttl INT,
            flags VARCHAR(50),
            classification VARCHAR(20),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        connection.commit()
    except mysql.connector.Error as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        connection.close()

# Extract packet features
def extract_packet_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_length = len(pkt)
        ttl = ip_layer.ttl

        src_port = dst_port = flags = None
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        return [src_ip, dst_ip, src_port, dst_port, protocol, packet_length, ttl, flags]
    return None

# Classify traffic using the ML model
def classify_traffic(data):
    df = pd.DataFrame([data], columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length', 'ttl', 'flags'])
    feature_cols = ['protocol', 'packet_length', 'ttl']
    #df['classification'] = model.predict(df[feature_cols].fillna(0))[0]
    prob = model.predict_proba(df[feature_cols].fillna(0))[0]
    df['classification'] = 'malicious' if prob[1] > 0.7 else 'non-malicious'
    return df

# Store results in MySQL
def store_to_mysql(df):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        for _, row in df.iterrows():
            cursor.execute('''INSERT INTO network (src_ip, dst_ip, src_port, dst_port, protocol, packet_length, ttl, flags, classification)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                           (row['src_ip'], row['dst_ip'], row['src_port'], row['dst_port'],
                            row['protocol'], row['packet_length'], row['ttl'], row['flags'],
                            row['classification']))
        connection.commit()
        print(f"Stored data: {row['classification']}")
    except mysql.connector.Error as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        connection.close()

# Callback to process live packets
def process_packet(pkt):
    data = extract_packet_features(pkt)
    if data:
        df = classify_traffic(data)
        store_to_mysql(df)

# Start live capture
def start_capture():
    print("Starting live network capture. Press Ctrl+C to stop.")
    create_table()
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_capture()
