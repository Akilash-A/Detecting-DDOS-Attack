
# 🚨 **DoS Attack Detection and SMS Alerting System** 🚨

This Python script monitors network traffic to detect potential **Denial-of-Service (DoS)** attacks by tracking IP packets. When a specific threshold of packets is detected within a time window, an **SMS alert** is sent using **Twilio**.

---

## 🛠️ **Prerequisites** 

Before running the script, make sure you have the following:

- **Python 3.x** installed 🐍
- **Scapy** library for packet sniffing: Install it using `pip install scapy` 📦
- **Twilio** library for sending SMS: Install it using `pip install twilio` 📦
- A **Twilio account** to generate the Account SID and Auth Token 🏢

---

## 📝 **Script Overview** 

### 🌐 **Twilio Credentials**

You will need the following credentials to send an SMS using Twilio:

- **ACCOUNT_SID**: Your Twilio Account SID
- **AUTH_TOKEN**: Your Twilio Auth Token
- **TWILIO_PHONE_NUMBER**: Your Twilio phone number 📱
- **TO_PHONE_NUMBER**: The recipient's phone number 📞

### 📊 **Detection Parameters**

The script uses the following parameters to detect **DoS attacks**:

- **PACKET_THRESHOLD**: The number of packets that need to be received within the `DETECTION_WINDOW` to trigger an alert. (default: 50 packets) ⚡
- **DETECTION_WINDOW**: The time window (in seconds) within which the packets are counted. (default: 5 seconds) ⏱️

---

## 💻 **Functionality**

1. **Packet Sniffing**: The script listens for incoming packets using **Scapy's** `sniff` function 🔍.
2. **Detection Logic**: It counts the number of packets from each unique **IP address**. If a single IP sends more than the threshold number of packets within the detection window, an alert is triggered 🚨.
3. **SMS Alerting**: When a **DoS attack** is detected, an **SMS** is sent to a specified phone number using the **Twilio API** 📲.

---

## 🛠️ **Code Breakdown**

```python
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
```

---

## 📦 **How to Run**

1. **Install the required packages**:
   - For **Debian/Ubuntu**:
     ```bash
     sudo apt install python3-pip
     pip3 install scapy twilio
     ```

   - For **Fedora**:
     ```bash
     sudo dnf install python3-pip
     pip3 install scapy twilio
     ```

   - For **Arch Linux**:
     ```bash
     sudo pacman -S python-pip
     pip install scapy twilio
     ```

2. **Replace the placeholder values** (`ACCOUNT_SID`, `AUTH_TOKEN`, `TWILIO_PHONE_NUMBER`, and `TO_PHONE_NUMBER`) in the script with your actual **Twilio credentials**.

3. **Run the script**:
   ```bash
   python3 dos_detection.py
   ```

---

## 🔐 **Security Considerations**

- Make sure to store your **Twilio credentials** securely, such as in **environment variables**, to prevent exposure 🔒.
- Be mindful of the **rate** at which the script sends SMS alerts to avoid excessive charges or potential service disruption 💸.

---

## 🚀 **Potential Improvements**

- **Automated Response**: Instead of just sending an alert, take automatic action to mitigate the **DoS attack** (e.g., block the IP) 🛡️.
- **Improved Detection**: Introduce additional logic for more complex **DoS attack detection**, such as **SYN flood attacks** 🌊.
- **Logging**: Implement **logging** for better tracking of detected attacks and actions taken 📜.

---

## 🔗 **Additional Resource**


To use it:

1. Clone the repository:
   ```bash
   git clone https://github.com/Akilash-A/Detecting-DDOS-Attack.git
   cd Detecting-DDOS-Attack
   ```

2. Run the tool:
   ```bash
   python3 ddos-attack-tool.py
   ```

---

## 📞 **Summary**

This script serves as a simple tool to detect potential **DoS attacks** and notify the administrator via **SMS**, providing a basic yet effective layer of network monitoring. It can be enhanced to address more advanced attacks and offer better responses 🔧.

---

Stay safe and keep your network secure! 🌐🔐
