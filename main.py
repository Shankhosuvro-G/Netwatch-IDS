import logging
import threading
from scapy.all import sniff
from Detectors.dns_amplification_detector import dns_amplification_detector
from Detectors.dns_spoof_detector import detect_dns_spoofing
from Detectors.ping_of_death_detector import detect_POD
from Detectors.port_scan_detector import port_scan_detector
from Detectors.syn_flood_detector import is_syn_flood
from Detectors.arp_poisoning_detector import arp_poisoning_detector


logging.basicConfig(
    filename='ids.log',
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)

def run_detector(detector_func):
    sniff(prn=detector_func, store=0)

if __name__ == "__main__":
    logging.info("IDS started. Awaiting packets...")

    detectors = [
        dns_amplification_detector,
        detect_dns_spoofing,
        detect_POD,
        port_scan_detector,
        is_syn_flood,
        arp_poisoning_detector
    ]

    threads = []
    for detector in detectors:
        thread = threading.Thread(target=run_detector, args=(detector,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
