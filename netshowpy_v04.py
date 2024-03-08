from scapy.all import get_if_list, sniff, ICMP, IP
from threading import Thread
import psutil
import keyboard
import time
import os
import socket

# Interface selection function.
import psutil

def choose_interface():
    interfaces = psutil.net_if_addrs()
    print("Network interfaces: ")
    interface_names = list(interfaces.keys())
    for i, interface_name in enumerate(interface_names):
        # show interface name and IP if exists.
        ip_address = None
        for address in interfaces[interface_name]:
            if address.family == socket.AF_INET:
                ip_address = address.address
                break
        print(f"{i+1}. {interface_name} - {ip_address if ip_address else 'No IP address'}")
    print("a. ALL (all interfaces)")

    choice = input(f"Select interface (1-{len(interface_names)} lub 'a'): ")
    if choice.lower() == 'a':
        return None  # in scapy - all interfaces.
    else:
        try:
            selected = int(choice) - 1
            if 0 <= selected < len(interface_names):
                return interface_names[selected]
            else:
                print("Wrong choice. All interfaces was selected.")
                return None
        except ValueError:
            print("Wrong choice. All interfaces was selected.")
            return None


# Initial Settings.
current_sort = 'tcp'
current_page = 0
connections_per_page = 32

def get_connections(sort_by='tcp'):
    conn_dict = {'tcp': [], 'udp': [], 'icmp': [], 'arp': []}
    for conn in psutil.net_connections(kind='all'):
        if conn.type == socket.SOCK_STREAM:
            conn_dict['tcp'].append(conn)
        elif conn.type == socket.SOCK_DGRAM:
            conn_dict['udp'].append(conn)

    return sorted(conn_dict[sort_by], key=lambda x: x.laddr.port if x.laddr else 0)

def print_connections(connections, page):
    start = page * connections_per_page
    end = start + connections_per_page
    for conn in connections[start:end]:
        print(f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else 'N/A'}:{conn.raddr.port if conn.raddr else 'N/A'} [{conn.status}]")

def refresh_display():
    os.system('cls' if os.name == 'nt' else 'clear')
    connections = get_connections(current_sort)
    print(f"Connections {current_sort.upper()} - Page {current_page + 1} from {len(connections) // connections_per_page + 1}")
    print_connections(connections, current_page)
    print("\nPress <- or ->, to change page. Space key - change sort order.")

def change_sort():
    global current_sort
    sorts = ['tcp', 'udp', 'icmp', 'arp']
    current_index = sorts.index(current_sort)
    current_sort = sorts[(current_index + 1) % len(sorts)]
    global current_page
    current_page = 0
    refresh_display()

def next_page():
    global current_page
    current_page += 1
    refresh_display()

def prev_page():
    global current_page
    if current_page > 0:
        current_page -= 1
    refresh_display()

# ICMP packets monitoring.
def monitor_icmp(interface):
    def monitor_icmp_packets(packet):
        if ICMP in packet:
            print(f"ICMP Packet: {packet[ICMP].summary()}")

    print("Monitoring ICMP packets. Press CTRL+C to stop.")
    sniff(iface=interface, filter="icmp", prn=monitor_icmp_packets, store=False)

# Interface selection by user.
interface = choose_interface()
print(f"Wybrano interfejs: {interface}")

# Monitoring thread separation
icmp_thread = Thread(target=monitor_icmp, args=(interface,), daemon=True)
icmp_thread.start()

# Keyboard 
keyboard.add_hotkey('space', change_sort)
keyboard.add_hotkey('right', next_page)
keyboard.add_hotkey('left', prev_page)

print("Space - sort change, cursor keys - change page.")
try:
    while True:
        refresh_display()
        time.sleep(1)
except KeyboardInterrupt:
    print("Finished.")
