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