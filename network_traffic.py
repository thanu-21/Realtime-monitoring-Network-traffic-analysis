# Import necessary libraries
import pandas as pd
import numpy as np
import mysql.connector
import joblib
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.ensemble import RandomForestClassifier

# Database Configuration
db_config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'network_traffic'
}

# Function to read PCAP and extract features
def extract_features_from_pcap(file_path):
    packets = rdpcap(file_path)
    features = []

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            protocol = ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            packet_length = len(pkt)
            ttl = ip_layer.ttl

            # TCP/UDP specific fields
            src_port = dst_port = flags = None
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            features.append([src_ip, dst_ip, src_port, dst_port, protocol, packet_length, ttl, flags])

    df = pd.DataFrame(features, columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length', 'ttl', 'flags'])
    return df

# Function to store data in MySQL
def store_to_mysql(df):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS traffic_datas (
            id INT AUTO_INCREMENT PRIMARY KEY,
            src_ip VARCHAR(255),
            dst_ip VARCHAR(255),
            src_port INT,
            dst_port INT,
            protocol INT,
            packet_length INT,
            ttl INT,
            flags VARCHAR(50),
            classification VARCHAR(20)
        )''')

        # Handle NaN values by replacing them with None
        df = df.replace({np.nan: None})

        for _, row in df.iterrows():
            cursor.execute('''INSERT INTO traffic_datas (src_ip, dst_ip, src_port, dst_port, protocol, packet_length, ttl, flags, classification)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''', (
                row['src_ip'], row['dst_ip'], row['src_port'], row['dst_port'],
                row['protocol'], row['packet_length'], row['ttl'], row['flags'],
                row['classification']
            ))

        connection.commit()
        print("Data inserted successfully")
    except mysql.connector.Error as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        connection.close()

# Function to classify traffic
def classify_traffic(df):
    # Load pre-trained ML model
    model = joblib.load('ml_model.joblib')
    feature_cols = ['protocol', 'packet_length', 'ttl']

    # Handle missing values and predict classification
    df['classification'] = model.predict(df[feature_cols].fillna(0))
    return df

# Main function
def main():
    file_path = 'demo4.pcap'
    print("Extracting Features from PCAP...")
    df = extract_features_from_pcap(file_path)

    print("Classifying Network Traffic...")
    df = classify_traffic(df)

    print("Storing Results to MySQL...")
    store_to_mysql(df)

    print("Process Completed. Data available for visualization in Grafana.")
    print("Extracted Data:")
    print(df.head())

if __name__ == "__main__":
    main()
