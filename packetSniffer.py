import customtkinter as ctk
from scapy.all import sniff, conf, Ether, IP
from datetime import datetime
import threading
import queue
import textwrap

# Define the global variable for the sniffer thread
sniffer_thread = None
stop_sniffing_flag = threading.Event()
packet_queue = queue.Queue()

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t - '

log_file = "packet_log.txt"

# GUI setup
app = ctk.CTk()
app.title("Packet Sniffer")
app.geometry("800x600")

# Define filtering options and text variables
filter_option = ctk.StringVar(value="All")
filter_ip = ctk.StringVar()
filter_mac = ctk.StringVar()
filter_type = ctk.StringVar()

def start_sniffing():
    global sniffer_thread, stop_sniffing_flag
    if not sniffer_thread or not sniffer_thread.is_alive():
        stop_sniffing_flag.clear()
        sniffer_thread = threading.Thread(target=main)
        sniffer_thread.start()

def stop_sniffing():
    stop_sniffing_flag.set()

def main():
    with open(log_file, 'a') as f:
        f.write("Packet Sniffing Log Started\n")
        f.write(get_filtering_details() + '\n')

    sniff(prn=lambda x: packet_queue.put(x), store=False, iface=conf.iface, stop_filter=should_stop_sniffing)

def should_stop_sniffing(packet):
    return stop_sniffing_flag.is_set()

def get_filtering_details():
    if filter_option.get() == "IP":
        return f"Filtering details: IP = {filter_ip.get()}"
    elif filter_option.get() == "MAC":
        return f"Filtering details: MAC = {filter_mac.get()}"
    elif filter_option.get() == "TYPE":
        return f"Filtering details: TYPE = {filter_type.get()}"
    else:
        return "Filtering details: None (Sniff All)"

def process_packet(packet):
    log_lines = []

    # Check if the packet has an IP and Ether layer
    if packet.haslayer(IP) and packet.haslayer(Ether):
        eth_layer = packet[Ether]
        ip_layer = packet[IP]

        # Apply filters
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

    # Write log lines to file
    with open(log_file, 'a') as f:
        for line in log_lines:
            f.write(line + '\n')

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def update_gui_log(text):
    log_textbox.configure(state="normal")
    log_textbox.insert(ctk.END, text)
    log_textbox.configure(state="disabled")
    log_textbox.yview(ctk.END)

def check_packet_queue():
    while not packet_queue.empty():
        packet = packet_queue.get()
        process_packet(packet)
    app.after(100, check_packet_queue)

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

# Top frame for start and stop buttons
top_frame = ctk.CTkFrame(app)
top_frame.pack(anchor='nw', pady=10, padx=10, fill='x')

start_button = ctk.CTkButton(top_frame, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=ctk.LEFT, padx=10, anchor='nw')

stop_button = ctk.CTkButton(top_frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(side=ctk.LEFT, padx=10, anchor='nw')

# Frame for filtering options and entry fields
filter_frame = ctk.CTkFrame(top_frame)
filter_frame.pack(side=ctk.LEFT, padx=20, anchor='nw')

all_radio = ctk.CTkRadioButton(filter_frame, text="Sniff All", variable=filter_option, value="All", command=show_filter_options)
all_radio.pack(anchor='w')
ip_radio = ctk.CTkRadioButton(filter_frame, text="IP", variable=filter_option, value="IP", command=show_filter_options)
ip_radio.pack(anchor='w')
mac_radio = ctk.CTkRadioButton(filter_frame, text="MAC", variable=filter_option, value="MAC", command=show_filter_options)
mac_radio.pack(anchor='w')
type_radio = ctk.CTkRadioButton(filter_frame, text="TYPE", variable=filter_option, value="TYPE", command=show_filter_options)
type_radio.pack(anchor='w')

ip_entry = ctk.CTkEntry(top_frame, textvariable=filter_ip)
mac_entry = ctk.CTkEntry(top_frame, textvariable=filter_mac)
type_entry = ctk.CTkEntry(top_frame, textvariable=filter_type)

# Text widget for displaying packet log
log_textbox = ctk.CTkTextbox(app, wrap='word')
log_textbox.pack(pady=10, padx=10, fill='both', expand=True)

app.after(100, check_packet_queue)
app.mainloop()
