Packet Sniffer GUI
Code Explanation
This project is a  python -based network packet sniffer with a graphical user interface (GUI) using customtkinter and scapy. It captures and analyzes network packets, with options to filter by IP address, MAC address, or packet type. Here's a breakdown of the main components and functionalities:

Imports and Global Variables
 
 
import customtkinter as ctk
from scapy.all import sniff, conf, Ether, IP
from datetime import datetime
import threading
import queue
import textwrap
customtkinter: Provides modern and customizable GUI components.
scapy: Used for network packet capturing and analysis.
datetime: Handles timestamps for packet logs.
threading: Manages concurrent execution of the packet sniffer.
queue: Manages packet data between threads.
textwrap: Formats multi-line data for display.
Global variables include:

sniffer_thread: Handles the sniffer thread.
stop_sniffing_flag: Controls stopping the sniffing process.
packet_queue: Queues packets for processing.
log_file: Specifies the file where packet logs are saved.
GUI Setup
 
 
app = ctk.CTk()
app.title("Packet Sniffer")
app.geometry("800x600")
app: Creates the main application window with a title and size.
Filtering Options
 
 
filter_option = ctk.StringVar(value="All")
filter_ip = ctk.StringVar()
filter_mac = ctk.StringVar()
filter_type = ctk.StringVar()
filter_option: Holds the current filter type (IP, MAC, TYPE, All).
filter_ip, filter_mac, filter_type: Store filter values for IP, MAC, and packet types.
Functions
start_sniffing()

Starts the packet sniffer in a separate thread if not already running.

 
 
def start_sniffing():
    global sniffer_thread, stop_sniffing_flag
    if not sniffer_thread or not sniffer_thread.is_alive():
        stop_sniffing_flag.clear()
        sniffer_thread = threading.Thread(target=main)
        sniffer_thread.start()
stop_sniffing()

Sets the flag to stop the sniffing process.

 
 
def stop_sniffing():
    stop_sniffing_flag.set()
main()

Handles packet sniffing and processing.

 
 
def main():
    with open(log_file, 'a') as f:
        f.write("Packet Sniffing Log Started\n")
        f.write(get_filtering_details() + '\n')

    sniff(prn=lambda x: packet_queue.put(x), store=False, iface=conf.iface, stop_filter=should_stop_sniffing)
sniff(): Captures packets and puts them in the queue.
should_stop_sniffing(packet)

Checks if the sniffing should be stopped based on the flag.

 
 
def should_stop_sniffing(packet):
    return stop_sniffing_flag.is_set()
get_filtering_details()

Returns a string describing the current filter settings.

 
 
def get_filtering_details():
    if filter_option.get() == "IP":
        return f"Filtering details: IP = {filter_ip.get()}"
    elif filter_option.get() == "MAC":
        return f"Filtering details: MAC = {filter_mac.get()}"
    elif filter_option.get() == "TYPE":
        return f"Filtering details: TYPE = {filter_type.get()}"
    else:
        return "Filtering details: None (Sniff All)"
process_packet(packet)

Processes and logs the packet based on its type and filter settings.

 
 
def process_packet(packet):
    log_lines = []

    if packet.haslayer(IP) and packet.haslayer(Ether):
        eth_layer = packet[Ether]
        ip_layer = packet[IP]

        if filter_option.get() == "IP" and filter_ip.get() not in [ip_layer.src, ip_layer.dst]:
            return
        if filter_option.get() == "MAC" and filter_mac.get() not in [eth_layer.src, eth_layer.dst]:
            return
        if filter_option.get() == "TYPE":
            if filter_type.get() == "TCP" and not packet.haslayer('TCP'):
                return
            if filter_type.get() == "UDP" and not packet.haslayer('UDP'):
                return
            if filter_type.get() == "ICMP" and not packet.haslayer('ICMP'):
                return

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        ip_info = f'\nIP Packet:\nSource_IP: {ip_layer.src}, Destination_IP: {ip_layer.dst}, Protocol: {ip_layer.proto}'
        mac_info = f'MAC Packet:\nSource_MAC: {eth_layer.src}, Destination_MAC: {eth_layer.dst}'

        log_lines.append(f"Timestamp: {timestamp}")
        log_lines.append(ip_info)
        log_lines.append(mac_info)

        update_gui_log(f"Timestamp: {timestamp}\n{ip_info}\n{mac_info}\n")

        if ip_layer.proto == 1:  # ICMP
            icmp_layer = packet['ICMP']
            icmp_info = (TAB_1 + 'ICMP Packet:\n' +
                         TAB_2 + f'Type: {icmp_layer.type}, Code: {icmp_layer.code}, Checksum: {icmp_layer.chksum}')
            log_lines.append(icmp_info)
            update_gui_log(f"{icmp_info}\n")

        elif ip_layer.proto == 6:  # TCP
            tcp_layer = packet['TCP']
            tcp_info = (TAB_1 + 'TCP Segment:\n' +
                        TAB_2 + f'Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}\n' +
                        TAB_2 + f'Sequence: {tcp_layer.seq}, Acknowledgment: {tcp_layer.ack}\n' +
                        TAB_2 + 'Flags:\n' +
                        TAB_3 + f'URG: {1 if tcp_layer.flags & 0x20 else 0}, '
                                f'ACK: {1 if tcp_layer.flags & 0x10 else 0}, '
                                f'PSH: {1 if tcp_layer.flags & 0x08 else 0}, '
                                f'RST: {1 if tcp_layer.flags & 0x04 else 0}, '
                                f'SYN: {1 if tcp_layer.flags & 0x02 else 0}, '
                                f'FIN: {1 if tcp_layer.flags & 0x01 else 0}')
            log_lines.append(tcp_info)
            update_gui_log(f"{tcp_info}\n")

        elif ip_layer.proto == 17:  # UDP
            udp_layer = packet['UDP']
            udp_info = (TAB_1 + 'UDP Segment:\n' +
                        TAB_2 + f'Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}, Length: {udp_layer.len}')
            log_lines.append(udp_info)
            update_gui_log(f"{udp_info}\n")

    with open(log_file, 'a') as f:
        for line in log_lines:
            f.write(line + '\n')
format_multi_line(prefix, string, size=80)

Formats multi-line data with a specified prefix and line width.

 
 
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
update_gui_log(text)

Updates the GUI log textbox with new packet information.

 
 
def update_gui_log(text):
    log_textbox.configure(state="normal")
    log_textbox.insert(ctk.END, text)
    log_textbox.configure(state="disabled")
    log_textbox.yview(ctk.END)
check_packet_queue()

Continuously checks the packet queue and processes packets.

 
 
def check_packet_queue():
    while not packet_queue.empty():
        packet = packet_queue.get()
        process_packet(packet)
    app.after(100, check_packet_queue)
show_filter_options()

Shows or hides filter entry fields based on the selected filter option.

 
 
def show_filter_options():
    if filter_option.get() == "IP":
        ip_entry.pack(side=ctk.RIGHT)
        mac_entry.pack_forget()
        type_entry.pack_forget()
    elif filter_option.get() == "MAC":
        mac_entry.pack(side=ctk.RIGHT)
        ip_entry.pack_forget()
        type_entry.pack_forget()
    elif filter_option.get() == "TYPE":
        type_entry.pack(side=ctk.RIGHT)
        ip_entry.pack_forget()
        mac_entry.pack_forget()
    else:
        ip_entry.pack_forget()
        mac_entry.pack_forget()
        type_entry.pack_forget()
GUI Components
ctk.CTk(): Main application window.
ctk.CTkButton(): Buttons for starting and stopping packet capture.
ctk.CTkRadioButton(): Radio buttons for selecting the filter type.
ctk.CTkEntry(): Entry fields for IP, MAC, and packet type filters.
ctk.CTkTextbox(): Textbox for displaying captured packet information.
Running the Application
Start the Application

 
 
app.mainloop()
Launches the GUI and handles user interactions.

Features
Real-Time Packet Capture: Captures network packets as they are transmitted over the network.
Filtering Options: Allows users to filter packets by IP address, MAC address, or packet type.
Log File: Saves detailed packet information to a log file for review.
GUI Interaction: Provides a user-friendly interface for controlling the sniffer and viewing packet data.
Multithreading: Uses threads to manage packet capture and processing without freezing the GUI.
Dynamic Filtering: Updates filter settings dynamically based on user selection.
