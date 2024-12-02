from scapy.all import sniff
from collections import defaultdict
from datetime import datetime
from twilio.rest import Client

# Twilio credentials
ACCOUNT_SID = 'ACCOUNT_SID' # Replace with your Account SID
AUTH_TOKEN = 'AUTH_TOKEN' # Replace with your Auth Token
TWILIO_PHONE_NUMBER = 'TWILIO_PHONE_NUMBER' # Replace with your Twilio phone number
TO_PHONE_NUMBER = 'TO_PHONE_NUMBER' # Replace with the recipient's phone number


# Detection parameters
PACKET_THRESHOLD = 50  # Trigger alert after 50 packets in DETECTION_WINDOW
DETECTION_WINDOW = 5   # Time window in seconds

# Initialize Twilio client
client = Client(ACCOUNT_SID, AUTH_TOKEN)

# Function to send SMS
def send_sms_alert(message):
    print(f"Sending SMS Alert: {message}")
    try:
        client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=TO_PHONE_NUMBER
        )
        print("SMS Alert sent successfully.")
    except Exception as e:
        print(f"Failed to send SMS: {e}")

# Packet detection function
def detect_dos(packet_counts, start_time, pkt):
    if 'IP' in pkt:
        src_ip = pkt['IP'].src
        packet_counts[src_ip] += 1

        # Check detection window
        elapsed = (datetime.now() - start_time[0]).total_seconds()
        if elapsed > DETECTION_WINDOW:
            for ip, count in packet_counts.items():
                if count > PACKET_THRESHOLD:
                    attack_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    send_sms_alert(f"DoS detected! IP: {ip}, Packets: {count} in {DETECTION_WINDOW} seconds. Time: {attack_time}")
            packet_counts.clear()
            start_time[0] = datetime.now()

# Main monitoring function
def monitor_traffic():
    packet_counts = defaultdict(int)
    start_time = [datetime.now()]  # Use a list to allow mutable reference
    print("Monitoring traffic for DoS attacks...")

    try:
        sniff(prn=lambda pkt: detect_dos(packet_counts, start_time, pkt), store=False)
    except Exception as e:
        print(f"An error occurred during packet sniffing: {e}")

# Run the monitoring function
if __name__ == "__main__":
    monitor_traffic()

