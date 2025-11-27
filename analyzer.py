import threading
import time
from collections import Counter
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.prompt import Prompt
from scapy.config import conf
from scapy.all import sniff

# A thread-safe class to store captured packet data and statistics
class PacketStats:
    def __init__(self):
        self.packets = []
        self.protocol_counts = Counter()
        self.lock = threading.Lock()
        self.start_time = time.time()

    def add_packet(self, packet):
        with self.lock:
            self.packets.append(packet)
            # Assuming Ethernet/IP layers for protocol check
            if 'IP' in packet:
                proto = packet['IP'].proto
                self.protocol_counts[self._proto_name(proto)] += 1
            elif 'ARP' in packet:
                self.protocol_counts['ARP'] += 1
            else:
                self.protocol_counts['Other'] += 1
    
    def _proto_name(self, proto_num):
        # Common protocol numbers
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protocol_map.get(proto_num, f'Proto-{proto_num}')

    def get_packets(self, limit=20):
        with self.lock:
            return self.packets[-limit:]

    def get_stats(self):
        with self.lock:
            total_packets = len(self.packets)
            elapsed_time = time.time() - self.start_time
            packets_per_second = total_packets / elapsed_time if elapsed_time > 0 else 0
            return self.protocol_counts, total_packets, packets_per_second

# --- UI Rendering ---
console = Console()
stats = PacketStats()

def generate_packets_table(packets_data) -> Table:
    """Generate a Rich Table for displaying packets."""
    table = Table(title="Live Network Packets")
    table.add_column("Time", style="cyan")
    table.add_column("Source IP", style="magenta")
    table.add_column("Dest IP", style="green")
    table.add_column("Protocol", style="yellow")
    table.add_column("Length", style="blue")

    for pkt_info in packets_data:
        table.add_row(
            pkt_info['time'],
            pkt_info['src'],
            pkt_info['dst'],
            pkt_info['proto'],
            str(pkt_info['len'])
        )
    return table

def generate_stats_table(protocol_counts, total_packets, pps) -> Table:
    """Generate a Rich Table for statistics."""
    table = Table(title="Traffic Statistics")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    
    table.add_row("Total Packets", str(total_packets))
    table.add_row("Packets/sec", f"{pps:.2f}")
    table.add_row("-" * 15, "-" * 15)
    
    if protocol_counts:
        table.add_row("[bold yellow]Protocol Breakdown[/bold yellow]", "")
        for proto, count in protocol_counts.most_common():
            table.add_row(f"  {proto}", str(count))
            
    return table

def generate_layout(packets_table, stats_table) -> Table:
    """Combine packets and stats tables into a single layout."""
    layout_table = Table(show_header=False, show_lines=False, padding=0, expand=True)
    layout_table.add_column()
    layout_table.add_row(stats_table)
    layout_table.add_row(packets_table)
    return layout_table

# --- Packet Sniffing ---
stop_sniffing = threading.Event()

def packet_callback(packet):
    """Callback function for each captured packet."""
    if stop_sniffing.is_set():
        return

    # Extract relevant info
    proto = "Other"
    src_ip, dst_ip = "N/A", "N/A"

    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        proto_num = packet['IP'].proto
        # Common protocol numbers
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto = protocol_map.get(proto_num, f'Proto-{proto_num}')
    elif 'ARP' in packet:
        src_ip = packet['ARP'].psrc
        dst_ip = packet['ARP'].pdst
        proto = "ARP"

    pkt_info = {
        'time': datetime.now().strftime("%H:%M:%S"),
        'src': src_ip,
        'dst': dst_ip,
        'proto': proto,
        'len': len(packet)
    }
    stats.add_packet(pkt_info)

def start_sniffer(interface_name):
    """Starts the Scapy sniffer in a background thread."""
    sniffer_thread = threading.Thread(
        target=sniff,
        kwargs={'iface': interface_name, 'prn': packet_callback, 'store': 0, 'stop_filter': lambda p: stop_sniffing.is_set()},
        daemon=True
    )
    sniffer_thread.start()
    console.print(f"[bold green]Sniffer started on interface '{interface_name}'. Press Ctrl+C to stop.[/bold green]")


def list_interfaces():
    """Lists available network interfaces using scapy's config."""
    # Force a refresh of the interface list
    conf.route.resync()
    
    iface_list = list(conf.ifaces.values())

    if not iface_list:
        console.print("[bold red]No network interfaces found. Ensure you have Npcap installed and that the script has administrator privileges.[/bold red]")
        return None

    table = Table(title="Available Network Interfaces")
    table.add_column("Index", style="bold")
    table.add_column("Name")
    table.add_column("Description")
    table.add_column("IP Address")

    iface_map = {}
    for i, iface in enumerate(iface_list):
        name = iface.name
        desc = iface.description
        ip = iface.ip
        
        table.add_row(str(i), name, desc, ip)
        iface_map[str(i)] = iface
    
    console.print(table)
    return iface_map


def main():
    """Main function to run the application."""
    console.print("[bold]Network Traffic Analyzer[/bold]")
    
    iface_map = list_interfaces()
    if not iface_map:
        return

    choice = Prompt.ask("Enter the index of the interface to monitor", choices=list(iface_map.keys()), show_choices=True)
    selected_interface = iface_map[choice]

    start_sniffer(selected_interface)

    try:
        with Live(console=console, screen=False, redirect_stderr=False, auto_refresh=False) as live:
            while not stop_sniffing.is_set():
                time.sleep(0.5)
                # Get data
                recent_packets = stats.get_packets()
                protocol_counts, total_packets, pps = stats.get_stats()

                # Generate UI elements
                packets_table = generate_packets_table(recent_packets)
                stats_table = generate_stats_table(protocol_counts, total_packets, pps)
                
                # Update the live display
                live.update(generate_layout(packets_table, stats_table), refresh=True)
                
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Stopping sniffer...[/bold yellow]")
        stop_sniffing.set()
        # Allow some time for the sniffer thread to stop cleanly
        time.sleep(1)
    finally:
        console.print("[bold red]Analysis stopped.[/bold red]")


if __name__ == "__main__":
    main()