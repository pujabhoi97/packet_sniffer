from scapy.all import sniff, TCP, IP, DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet6 import IPv6
import threading

# Shared data structure for captured traffic
captured_data = {
    "tcp": 0,
    "http": 0,
    "dns": 0,
    "http_hosts": [],
    "dns_queries": [],
    "tcp_sources": []
}

# Lock for thread-safe data access
lock = threading.Lock()

def process_packet(packet):
    print("[+] Packet captured:", packet.summary())

    with lock:
        # DNS Traffic
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            captured_data["dns"] += 1
            dns_query = packet[DNSQR].qname.decode(errors="ignore")
            print("[DNS] Query:", dns_query)
            if dns_query not in captured_data["dns_queries"]:
                captured_data["dns_queries"].append(dns_query)
                if len(captured_data["dns_queries"]) > 10:
                    captured_data["dns_queries"].pop(0)

        # TCP Traffic
        if packet.haslayer(TCP):
            captured_data["tcp"] += 1
            if packet.haslayer(IP):
                src_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
            else:
                src_ip = "Unknown"
            print("[TCP] Source IP:", src_ip)
            if src_ip not in captured_data["tcp_sources"]:
                captured_data["tcp_sources"].append(src_ip)
                if len(captured_data["tcp_sources"]) > 10:
                    captured_data["tcp_sources"].pop(0)

        # HTTP Traffic
        if packet.haslayer(HTTPRequest):
            captured_data["http"] += 1
            host = packet[HTTPRequest].Host.decode(errors="ignore")
            print("[HTTP] Host:", host)
            if host not in captured_data["http_hosts"]:
                captured_data["http_hosts"].append(host)
                if len(captured_data["http_hosts"]) > 10:
                    captured_data["http_hosts"].pop(0)

def start_sniffing():
    print("[*] Starting packet sniffing...")
    sniff(prn=process_packet, store=False)
