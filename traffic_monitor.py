import pymysql
import csv
from datetime import datetime

# Database Connection
conn = pymysql.connect(host='localhost', user='root', password='root', database='network_traffic')
cursor = conn.cursor()

# Malicious IPs List (Add known malicious IPs here)
malicious_ips = ["192.168.1.100", "203.0.113.45"]

# Function to classify traffic based on source IP and length
def classify_traffic(src_ip, length):
    if src_ip in malicious_ips or (length.isdigit() and int(length) > 1500):  
        return "Malicious"
    return "Non-Malicious"

# Read CSV and insert into MySQL
with open('live_capture.csv', 'r') as file:
    csv_reader = csv.reader(file)
    next(csv_reader)  # Skip header row

    for row in csv_reader:
        print("Row Data:", row)  # Debugging line

        try:
            # Extract and clean timestamp
            timestamp_str = row[0].strip('\\') + row[1]  # Remove extra backslash and join
            timestamp_str = timestamp_str.replace("India Standard Time", "").strip()  # Remove timezone
            timestamp_str = timestamp_str[:23]  # Keep only up to 6-digit microseconds

            # Convert to datetime
            timestamp = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S.%f")  
        except ValueError as e:
            print(f"Skipping invalid timestamp: {timestamp_str}")
            continue  # Skip rows with invalid timestamp

        if len(row) < 6 or not row[2] or not row[3]:  
            print("Skipping row due to missing IP data.")
            continue

        src_ip = row[2]
        dst_ip = row[3]
        protocol = row[4] if row[4] else "Unknown"
        length = row[5] if row[5] else "0"

        classification = classify_traffic(src_ip, length)

        # Print progress for debugging
        print(f"Inserting data: {timestamp}, {src_ip}, {dst_ip}, {protocol}, {length}, {classification}")

        sql = "INSERT INTO traffic_data (timestamp, src_ip, dst_ip, protocol, length, classification) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(sql, (timestamp, src_ip, dst_ip, protocol, length, classification))
        conn.commit()

        # Print confirmation after each insert
        print("Data inserted successfully")

print("Traffic data stored in MySQL successfully!")
conn.close()
