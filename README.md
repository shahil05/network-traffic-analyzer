# Network Traffic Analyzer

A web app that accepts `.pcap` Wireshark capture files and visualizes network traffic — protocol breakdown, top source/destination IPs, and packet statistics.

## Built With
- Python, Flask, Scapy
- Chart.js
- Deployed via Vercel

## Features
- Upload any `.pcap` file
- Protocol breakdown — TCP, UDP, DNS, HTTP, HTTPS
- Top 10 source and destination IPs
- Interactive doughnut and bar charts
- Clean dark dashboard UI

## Run Locally
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Then open `http://127.0.0.1:5000`