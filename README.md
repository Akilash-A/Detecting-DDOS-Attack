
# 🚨 **DoS Attack Detection & SMS Alerting System** 🚨

## 📚 **General Overview**

This Python-based **DoS Attack Detection & SMS Alerting System** monitors network traffic in real-time for signs of Denial of Service (DoS) attacks and sends an **SMS alert** via Twilio when suspicious activity is detected. It's designed to work seamlessly with **Scapy** for packet sniffing and **Twilio API** for SMS notification.

### 💡 **Key Features**
1. **Real-time Monitoring**: Uses Scapy to sniff network packets in real-time.
2. **DoS Attack Detection**: Detects and triggers alerts based on packet counts from specific IPs within a defined window.
3. **SMS Alerts**: Sends an SMS alert via Twilio when suspicious activity (DoS attack) is detected.
4. **Customizable Detection Parameters**: You can set the packet threshold and detection window as per your requirements.
5. **Simple Setup**: Easy to deploy with clear instructions.

## 🛠️ **How to Setup & Use**

### 1. **Clone the Repository**

First, clone the project repository:

```bash
git clone https://github.com/Akilash-A/Detecting-DDOS-Attack.git
cd Detecting-DDOS-Attack
```

### 2. **Install Dependencies**

For Linux-based systems (Ubuntu/Debian/Fedora), use the following commands to install the necessary dependencies:

#### For Ubuntu/Debian:

```bash
sudo apt update
sudo apt install python3-pip
sudo apt install python3-scapy
sudo apt install python3-twilio
```

#### For Fedora:

```bash
sudo dnf install python3-pip
sudo dnf install python3-scapy
sudo dnf install python3-twilio
```

#### Install Python Dependencies:

```bash
python3 -m pip install -r requirements.txt
```

### 3. **Configure Twilio Credentials**

In the Python script, replace the placeholders with your **Twilio Account SID**, **Auth Token**, **Twilio Phone Number**, and the **Recipient Phone Number**:

```python
ACCOUNT_SID = 'ACCOUNT_SID'  # Replace with your Account SID
AUTH_TOKEN = 'AUTH_TOKEN'  # Replace with your Auth Token
TWILIO_PHONE_NUMBER = 'TWILIO_PHONE_NUMBER'  # Replace with your Twilio phone number
TO_PHONE_NUMBER = 'TO_PHONE_NUMBER'  # Replace with the recipient's phone number
```

### 4. **Run the Script**

Execute the script to start monitoring network traffic and send alerts:

```bash
python3 ddos-attack-tool.py
```

🚀 **The system will start monitoring network traffic and send SMS alerts in case of a potential DoS attack!**

## 🔐 **Security Considerations**

- **Environment Variables**: Store your Twilio credentials in environment variables to ensure that sensitive information isn't exposed in the code.
- **Network Security**: Make sure you run this tool in a controlled environment and have permission to sniff network traffic.

## ⚡ **Error Handling**

The script includes basic error handling to ensure that the monitoring process is resilient. It catches exceptions during packet sniffing and SMS alert sending, ensuring the system continues to run smoothly.

## 💡 **Potential Improvements**
- **Multi-Network Support**: Extend the system to monitor multiple network interfaces.
- **Improved Logging**: Implement advanced logging to capture and review attack patterns.
- **Web Dashboard**: Develop a web interface to display the attack statistics and logs in real-time.

## 📈 **Usage Example**

Once the script is running, the system will continuously monitor network traffic. When an attack is detected, it will send an SMS to the configured recipient with a detailed message:

```
DoS detected! IP: 192.168.1.1, Packets: 60 in 5 seconds. Time: 2024-12-02 10:30:45
```

📱 **SMS Alert**: This SMS will be sent to the specified recipient.

## 🎯 **Contributing**

Contributions are welcome! If you have suggestions or improvements, feel free to open an issue or submit a pull request.

## 🌐 **GitHub Repository**
[Link to the GitHub Repository](https://github.com/Akilash-A)

---

🔒 **Disclaimer**: Please ensure you have proper authorization to monitor and analyze network traffic. Unauthorized packet sniffing may be illegal in some jurisdictions. Always use ethical practices when working with networking tools. 

