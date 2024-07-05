import logging
from scapy.all import TCP, IP, sniff
from collections import defaultdict

syn_counts=[]
logger=logging.getLogger(__name__)
def is_syn_flood(packet):
    logger.info("SYn flood detector started.")
    if packet.haslayer(TCP) and packet[TCP].flags=="S" and packet.haslayer(IP):
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst
        syn_counts.append(ip_src)
        if len(syn_counts) > 100:
            logger.info(f"SYN flood detected: {ip_src} -> {ip_dst}")
sniff(filter="tcp", prn=is_syn_flood, store=0,timeout=10)       