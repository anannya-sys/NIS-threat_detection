from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_packet(packet):
    """
    Parses a raw Scapy packet into a JSON-serializable dictionary
    rich with metadata for the frontend visualization.
    """
    # 1. Initialize Default Structure
    packet_info = {
        "timestamp": datetime.now().isoformat(),
        "length": len(packet),
        "protocol": "Ethernet",
        "src": "N/A",
        "dst": "N/A",
        "src_port": None,
        "dst_port": None,
        "info": "",
        "raw": "",
        "layers": [],
        # Extended fields for frontend details
        "src_mac": None,
        "dst_mac": None,
        "tcp_flags": None,
        "seq": None,
        "ack": None,
        "ttl": None,
        "icmp_type": None,
        "icmp_code": None,
        "dns_query": None,
        "dns_answers": [],
        "http_method": None,
        "http_host": None,
        "http_path": None
    }

    try:
        # 2. Layer 2: Ethernet / Data Link
        if packet.haslayer(Ether):
            packet_info["src_mac"] = packet[Ether].src
            packet_info["dst_mac"] = packet[Ether].dst
            packet_info["src"] = packet[Ether].src
            packet_info["dst"] = packet[Ether].dst
            packet_info["layers"].append("Ethernet")
            packet_info["info"] = "Ethernet frame"

        # 3. Layer 2.5: ARP
        if packet.haslayer(ARP):
            packet_info["protocol"] = "ARP"
            packet_info["src"] = packet[ARP].psrc
            packet_info["dst"] = packet[ARP].pdst
            packet_info["info"] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            packet_info["layers"].append("ARP")
            return packet_info  # Return early for ARP

        # 4. Layer 3: IP (IPv4)
        if packet.haslayer(IP):
            packet_info["src"] = packet[IP].src
            packet_info["dst"] = packet[IP].dst
            packet_info["ttl"] = packet[IP].ttl
            packet_info["layers"].append("IPv4")
            packet_info["protocol"] = "IP" # Default, updated below

            # 5. Layer 4: TCP
            if packet.haslayer(TCP):
                packet_info["protocol"] = "TCP"
                packet_info["layers"].append("TCP")
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["seq"] = packet[TCP].seq
                packet_info["ack"] = packet[TCP].ack
                
                # TCP Flags Analysis
                flags = packet[TCP].flags
                flag_str = ""
                if flags & 0x02: flag_str += "SYN "
                if flags & 0x10: flag_str += "ACK "
                if flags & 0x01: flag_str += "FIN "
                if flags & 0x04: flag_str += "RST "
                if flags & 0x08: flag_str += "PSH "
                packet_info["tcp_flags"] = flag_str.strip()
                packet_info["info"] = f"{packet[TCP].sport} → {packet[TCP].dport} [{packet_info['tcp_flags']}]"

                # Application Layer: HTTP Detection
                if packet.haslayer(Raw):
                    try:
                        payload = bytes(packet[Raw].load)
                        payload_str = payload[:200].decode('utf-8', errors='ignore')
                        
                        # Detect HTTP Request
                        methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ']
                        if any(payload_str.startswith(m) for m in methods):
                            packet_info["protocol"] = "HTTP"
                            packet_info["layers"].append("HTTP")
                            lines = payload_str.split('\r\n')
                            req_line = lines[0].split(' ')
                            packet_info["http_method"] = req_line[0]
                            packet_info["http_path"] = req_line[1] if len(req_line) > 1 else "/"
                            packet_info["info"] = f"HTTP {req_line[0]} {packet_info['http_path']}"
                            
                            # Extract Host
                            for line in lines:
                                if line.lower().startswith("host:"):
                                    packet_info["http_host"] = line.split(":", 1)[1].strip()

                        # Detect HTTP Response
                        elif payload_str.startswith("HTTP/"):
                            packet_info["protocol"] = "HTTP"
                            packet_info["layers"].append("HTTP")
                            packet_info["info"] = f"HTTP Response {payload_str.split(' ', 1)[1].split(chr(13))[0]}"
                    except:
                        pass
                
                # Port-based Service Guessing
                if packet_info["protocol"] == "TCP":
                    if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        packet_info["protocol"] = "HTTPS"
                    elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                        packet_info["protocol"] = "SSH"

            # 6. Layer 4: UDP
            elif packet.haslayer(UDP):
                packet_info["protocol"] = "UDP"
                packet_info["layers"].append("UDP")
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                packet_info["info"] = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"

                # Application Layer: DNS
                if packet.haslayer(DNS):
                    packet_info["protocol"] = "DNS"
                    packet_info["layers"].append("DNS")
                    dns = packet[DNS]
                    
                    # DNS Query
                    if dns.qr == 0 and dns.qd:
                        qname = dns.qd.qname.decode('utf-8', errors='ignore')
                        packet_info["dns_query"] = qname
                        packet_info["info"] = f"DNS Query: {qname}"
                    
                    # DNS Response
                    elif dns.qr == 1:
                        packet_info["info"] = "DNS Response"
                        if dns.an:
                            # Extract answers (simplified)
                            for i in range(dns.ancount):
                                rdata = dns.an[i].rdata
                                if isinstance(rdata, bytes):
                                    packet_info["dns_answers"].append(rdata.decode('utf-8', errors='ignore'))
                                else:
                                    packet_info["dns_answers"].append(str(rdata))
                
                # Port-based Service Guessing
                elif packet[UDP].dport == 67 or packet[UDP].sport == 67:
                    packet_info["protocol"] = "DHCP"
                elif packet[UDP].dport == 123 or packet[UDP].sport == 123:
                    packet_info["protocol"] = "NTP"

            # 7. Layer 4: ICMP
            elif packet.haslayer(ICMP):
                packet_info["protocol"] = "ICMP"
                packet_info["layers"].append("ICMP")
                packet_info["icmp_type"] = packet[ICMP].type
                packet_info["icmp_code"] = packet[ICMP].code
                
                type_map = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
                type_desc = type_map.get(packet[ICMP].type, f"Type {packet[ICMP].type}")
                packet_info["info"] = f"ICMP {type_desc}"

        # 8. Raw Hex Dump (for the 'Hex View' in frontend)
        if packet.haslayer(Raw):
            raw_bytes = bytes(packet[Raw].load)
            packet_info["raw"] = raw_bytes.hex(' ')

    except Exception as e:
        # Fallback for any parsing errors
        logger.error(f"Error parsing packet: {e}")
        packet_info["info"] = "Error parsing packet"

    return packet_info