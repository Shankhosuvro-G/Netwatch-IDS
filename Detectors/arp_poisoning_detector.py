from scapy.all import ARP,sniff
import logging

logger=logging.getLogger(__name__)
arp_cache={}

def arp_poisoning_detector(packet):
    logger.info("ARP poisoning detector started.")
    if packet.haslayer(ARP) and packet[ARP].op==2:
        ip_src=packet[ARP].psrc
        mac_src=packet[ARP].hwsrc

        if ip_src  in arp_cache and arp_cache[ip_src] != mac_src:
            logger.info(f"ARP Poisoning detected: {ip_src} is being spoofed")
        arp_cache[ip_src]=mac_src    
sniff(filter="arp",prn=arp_poisoning_detector,timeout=10,store=0)        