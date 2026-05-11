from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR

def parse_pcap(filepath):
    packets = rdpcap(filepath)


    protocol_counts = {"TCP": 0, "UDP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "Other": 0}
    ip_sources = {}
    ip_destinations = {}

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            ip_sources[src] = ip_sources.get(src, 0) + 1
            ip_destinations[dst] = ip_destinations.get(dst, 0) + 1
            if TCP in packet:
                port = packet[TCP].dport
                if port == 80:
                    protocol_counts["HTTP"] += 1
                elif port == 443:
                    protocol_counts["HTTPS"] += 1
                else:
                    protocol_counts["TCP"] += 1

            elif UDP in packet:
                if DNS in packet:
                    protocol_counts["DNS"] += 1
                else:
                    protocol_counts["UDP"] += 1

            else:
                protocol_counts["Other"] += 1

    top_sources = sorted(ip_sources.items(), key=lambda x: x[1], reverse=True)[:10]
    top_destinations = sorted(ip_destinations.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_packets": len(packets),
        "protocol_counts": protocol_counts,
        "top_sources": top_sources,
        "top_destinations": top_destinations
    }
def detect_anomalies(filepath):
    packets = rdpcap(filepath)
    
    ip_port_map = {}
    ip_packet_counts = {}
    suspicious_ports = {4444, 1337, 8888, 31337, 6666, 9999}
    anomalies = []
    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            ip_packet_counts[src] = ip_packet_counts.get(src, 0) + 1

            if TCP in packet:
                dport = packet[TCP].dport
                if src not in ip_port_map:
                    ip_port_map[src] = set()
                ip_port_map[src].add(dport)

                if dport in suspicious_ports:
                    anomalies.append({
                        "type": "Suspicious Port",
                        "ip": src,
                        "detail": f"Traffic on port {dport} — known malware port",
                        "severity": "high"
                    })
                    # Port scan detection
    for ip, ports in ip_port_map.items():
        if len(ports) > 10:
            anomalies.append({
                "type": "Port Scan",
                "ip": ip,
                "detail": f"Contacted {len(ports)} different ports — possible port scan",
                "severity": "high"
            })

    # High volume detection
    if ip_packet_counts:
        avg = sum(ip_packet_counts.values()) / len(ip_packet_counts)
        for ip, count in ip_packet_counts.items():
            if count > avg * 3:
                anomalies.append({
                    "type": "High Volume",
                    "ip": ip,
                    "detail": f"Sent {count} packets — {round(count/avg, 1)}x above average",
                    "severity": "medium"
                })

    return anomalies