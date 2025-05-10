#!/usr/bin/env python3
"""
Network Sniffer and Analyzer
Author: Your Name
Date: YYYY-MM-DD
"""

import scapy.all as scapy
from scapy.layers import http
import argparse
import datetime
import signal
import sys
import logging
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sniffer.log'),
        logging.StreamHandler()
    ]
)

class NetworkSniffer:
    def __init__(self, interface, filter_exp=None, output_file=None):
        self.interface = interface
        self.filter_exp = filter_exp
        self.output_file = output_file
        self.packet_count = 0
        self.running = False
        self.protocol_stats = defaultdict(int)
        self.traffic_stats = {'total': 0, 'incoming': 0, 'outgoing': 0}
        
        # Set up signal handler for graceful exit
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C interrupt"""
        logging.info("\nStopping sniffer...")
        self.running = False
        self.display_stats()
        sys.exit(0)
        
    def start_sniffing(self):
        """Start packet sniffing"""
        logging.info(f"Starting sniffer on interface {self.interface}")
        if self.filter_exp:
            logging.info(f"Filter expression: {self.filter_exp}")
            
        self.running = True
        scapy.sniff(
            iface=self.interface,
            prn=self.process_packet,
            filter=self.filter_exp,
            store=False
        )
        
    def process_packet(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        
        # Log basic packet info
        self.log_packet(packet)
        
        # Update statistics
        self.update_stats(packet)
        
        # Analyze HTTP traffic if present
        if packet.haslayer(http.HTTPRequest):
            self.process_http_request(packet)
            
    def log_packet(self, packet):
        """Log packet information"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        summary = packet.summary()
        
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(f"{timestamp} - {summary}\n")
        
        if self.packet_count % 10 == 0:
            logging.info(f"Packets captured: {self.packet_count}")
            
    def update_stats(self, packet):
        """Update statistics about captured packets"""
        # Protocol statistics
        if packet.haslayer(scapy.IP):
            self.protocol_stats['IP'] += 1
            if packet.haslayer(scapy.TCP):
                self.protocol_stats['TCP'] += 1
            elif packet.haslayer(scapy.UDP):
                self.protocol_stats['UDP'] += 1
            elif packet.haslayer(scapy.ICMP):
                self.protocol_stats['ICMP'] += 1
                
        # Traffic direction (simplified)
        if packet.haslayer(scapy.IP):
            # This is a very basic way to determine direction
            # In a real application, you'd compare with local IPs
            if packet[scapy.IP].dst.startswith('192.168'):
                self.traffic_stats['incoming'] += 1
            else:
                self.traffic_stats['outgoing'] += 1
            self.traffic_stats['total'] += packet[scapy.IP].len
        
    def process_http_request(self, packet):
        """Extract and log HTTP request information"""
        http_layer = packet[http.HTTPRequest].fields
        ip_layer = packet[scapy.IP].fields
        
        logging.info("\n[HTTP Request]")
        logging.info(f"Source: {ip_layer['src']}:{packet[scapy.TCP].sport}")
        logging.info(f"Destination: {ip_layer['dst']}:{packet[scapy.TCP].dport}")
        logging.info(f"Host: {http_layer['Host'].decode()}")
        logging.info(f"Path: {http_layer['Path'].decode()}")
        logging.info(f"Method: {http_layer['Method'].decode()}")
        
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            try:
                logging.info(f"Payload: {load.decode()}")
            except UnicodeDecodeError:
                logging.info("Payload: [Binary data]")
                
    def display_stats(self):
        """Display capture statistics"""
        logging.info("\nCapture Statistics:")
        logging.info(f"Total packets captured: {self.packet_count}")
        
        logging.info("\nProtocol Distribution:")
        for proto, count in self.protocol_stats.items():
            logging.info(f"{proto}: {count} packets")
            
        logging.info("\nTraffic Statistics:")
        logging.info(f"Total bytes: {self.traffic_stats['total']}")
        logging.info(f"Incoming packets: {self.traffic_stats['incoming']}")
        logging.info(f"Outgoing packets: {self.traffic_stats['outgoing']}")

def get_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-i", "--interface", dest="interface", 
                        help="Network interface to sniff on", required=True)
    parser.add_argument("-f", "--filter", dest="filter_exp", 
                        help="BPF filter expression", default=None)
    parser.add_argument("-o", "--output", dest="output_file", 
                        help="Output file to save packets", default=None)
    return parser.parse_args()

def main():
    """Main function"""
    args = get_arguments()
    sniffer = NetworkSniffer(
        interface=args.interface,
        filter_exp=args.filter_exp,
        output_file=args.output_file
    )
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()
