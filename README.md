# 🛡️ Lightweight Host Intrusion Detection System (HIDS)

## 📌 Overview
This project implements a lightweight Host Intrusion Detection System (HIDS) that monitors system activity in real time, detects suspicious processes, and identifies unusual network connections.

It is designed to simulate real-world system monitoring and security detection used in IT support and cybersecurity roles.

---

## 🚀 Features

- 📊 Real-time CPU and memory monitoring  
- ⚠️ Detection of abnormal resource usage  
- 🔍 Suspicious process identification (e.g. netcat, nmap)  
- 🌐 Detection of external network connections  
- 📝 Logging system for tracking security events  
- 🚨 Risk scoring system for threat evaluation  

---

## 🧠 How It Works

1. Collect system data using `psutil`
2. Analyze running processes and network connections
3. Detect anomalies based on predefined rules
4. Assign a risk score based on detected threats
5. Log and display alerts

---

## ⚙️ Tech Stack

- Python  
- psutil  

---

## ▶️ How to Run

```bash
pip install -r requirements.txt
python main.py
