import tkinter as tk
from tkinter import ttk, messagebox
import threading
from scapy.all import get_if_list, sniff, Ether, IP, ARP, TCP, UDP

class NetWhisperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetWhisper GUI")
        
        self.interface_var = tk.StringVar()
        self.packet_type_var = tk.StringVar(value="All")
        self.packet_count_var = tk.StringVar(value="0")
        self.output_text = tk.Text(self.root, wrap=tk.WORD, state=tk.DISABLED)
        self.start_button = ttk.Button(self.root, text="Start", command=self.start_sniffer)
        self.pause_button = ttk.Button(self.root, text="Pause", command=self.pause_sniffer, state=tk.DISABLED)
        self.save_button = ttk.Button(self.root, text="Save", command=self.save_packets, state=tk.DISABLED)
        self.read_button = ttk.Button(self.root, text="Read", command=self.read_packets)
        
        self.sniffer_thread = None
        self.update_output = None
        self.sniffing = False
        
        self.captured_packets = []  # To store captured packets
        
        self.init_ui()
        self.populate_interface_list()
    
    def populate_interface_list(self):
        interfaces = get_if_list()
        self.interface_var.set(interfaces[0] if interfaces else "")
        self.interface_combobox["values"] = interfaces
    
    def init_ui(self):
        interface_label = ttk.Label(self.root, text="Select Interface:")
        interface_label.grid(row=0, column=0, padx=10, pady=5)
        
        self.interface_combobox = ttk.Combobox(self.root, textvariable=self.interface_var)
        self.interface_combobox.grid(row=0, column=1, padx=10, pady=5)
        
        packet_type_label = ttk.Label(self.root, text="Select Packet Type:")
        packet_type_label.grid(row=1, column=0, padx=10, pady=5)
        
        packet_type_combobox = ttk.Combobox(self.root, textvariable=self.packet_type_var, values=["All", "TCP", "UDP", "ARP", "SSL", "DNS", "QUIC"])
        packet_type_combobox.grid(row=1, column=1, padx=10, pady=5)
        
        packet_count_label = ttk.Label(self.root, text="Packet Count:")
        packet_count_label.grid(row=2, column=0, padx=10, pady=5)
        
        packet_count_entry = ttk.Entry(self.root, textvariable=self.packet_count_var)
        packet_count_entry.grid(row=2, column=1, padx=10, pady=5)
        
        self.start_button.grid(row=3, column=0, padx=10, pady=10)
        self.pause_button.grid(row=3, column=1, padx=10, pady=10)
        self.save_button.grid(row=4, column=0, padx=10, pady=5)
        self.read_button.grid(row=4, column=1, padx=10, pady=5)
        
        self.output_text.grid(row=5, columnspan=2, padx=10, pady=10)
        
        # Create a Treeview widget for tabular display
        self.treeview = ttk.Treeview(self.root, columns=("Source", "Destination", "Protocol", "Length", "Info"), show="headings")
        self.treeview.heading("Source", text="Source IP")
        self.treeview.heading("Destination", text="Destination IP")
        self.treeview.heading("Protocol", text="Protocol")
        self.treeview.heading("Length", text="Length")
        self.treeview.heading("Info", text="Info")
        self.treeview.column("Source", width=150)
        self.treeview.column("Destination", width=150)
        self.treeview.column("Protocol", width=100)
        self.treeview.column("Length", width=80)
        self.treeview.column("Info", width=200)
        self.treeview.grid(row=6, columnspan=2, padx=10, pady=10, sticky="nsew")

        # Set up the behavior to display detailed packet info upon clicking
        self.treeview.bind("<ButtonRelease-1>", self.show_detailed_info)
        
        self.root.grid_rowconfigure(5, weight=1)  # Allow the output Text widget to expand
        self.root.grid_columnconfigure(0, weight=1)  # Allow the Treeview widget to expand
    
    def show_detailed_info(self, event):
        selected_item = self.treeview.selection()
        if selected_item:
            packet_index = self.treeview.index(selected_item)  # Get the selected item's index
            packet = self.captured_packets[packet_index]  # Get the packet from captured_packets

            # Create a Text widget to display detailed packet information
            detailed_text = tk.Text(self.root, wrap=tk.WORD)
            detailed_text.grid(row=7, columnspan=2, padx=10, pady=10, sticky="nsew")

            # Show detailed packet information using Scapy's show method
            detailed_text.insert(tk.END, packet.show(dump=True))
            detailed_text.config(state=tk.DISABLED)

    def start_sniffer(self):
        if self.sniffing:
            return
        
        self.sniffing = True
        
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        
        self.start_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.read_button.config(state=tk.DISABLED)
        
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()
    
    def sniff_packets(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        
        interface = self.interface_var.get()
        packet_type = self.packet_type_var.get()
        packet_count = int(self.packet_count_var.get())
        
        filter_expr = ""
        if packet_type == "TCP":
            filter_expr = "tcp"
        elif packet_type == "UDP":
            filter_expr = "udp"
        elif packet_type == "ARP":
            filter_expr = "arp"
        elif packet_type == "SSL":
            filter_expr = "port 443"
        elif packet_type == "DNS":
            filter_expr = "port 53"
        elif packet_type == "QUIC":
            filter_expr = "udp port 443"
        
        packets = sniff(iface=interface, filter=filter_expr, count=packet_count)
        
        self.output_text.config(state=tk.NORMAL)
        for packet in packets:
            packet_info = self.extract_packet_info(packet)
            formatted_info = "\n".join([f"{field}: {value}" for field, value in packet_info.items()])
            self.output_text.insert(tk.END, formatted_info + "\n")
            self.output_text.see(tk.END)
            self.root.update()  # Update the GUI to display packets in real-time
            
            self.update_treeview(packet)
        
        self.output_text.config(state=tk.DISABLED)
        
        self.start_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.read_button.config(state=tk.NORMAL)
        
        self.sniffing = False
    
    def extract_packet_info(self, packet):
        packet_info = {}
        if IP in packet:
            packet_info["Source"] = packet[IP].src
            packet_info["Destination"] = packet[IP].dst
            packet_info["Protocol"] = packet[IP].proto
            packet_info["Length"] = len(packet)
            packet_info["Info"] = packet.summary()
        elif ARP in packet:
            packet_info["Source"] = packet[ARP].psrc
            packet_info["Destination"] = packet[ARP].pdst
            packet_info["Protocol"] = "ARP"
            packet_info["Length"] = len(packet)
            packet_info["Info"] = packet.summary()
        elif TCP in packet:
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                packet_info["Source"] = packet[IP].src
                packet_info["Destination"] = packet[IP].dst
                packet_info["Protocol"] = "SSL"
                packet_info["Length"] = len(packet)
                packet_info["Info"] = packet.summary()
        elif UDP in packet:
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    packet_info["Source"] = packet[IP].src
                    packet_info["Destination"] = packet[IP].dst
                    packet_info["Protocol"] = "DNS"
                    packet_info["Length"] = len(packet)
                    packet_info["Info"] = packet.summary()
                elif packet[UDP].dport == 443 or packet[UDP].sport == 443:
                    packet_info["Source"] = packet[IP].src
                    packet_info["Destination"] = packet[IP].dst
                    packet_info["Protocol"] = "QUIC"
                    packet_info["Length"] = len(packet)
                    packet_info["Info"] = packet.summary()
        return packet_info
    
    def update_treeview(self, packet):
        self.captured_packets.append(packet)  # Store the captured packet
        packet_info = self.extract_packet_info(packet)
        self.treeview.insert("", "end", values=(
            packet_info.get("Source", ""),
            packet_info.get("Destination", ""),
            packet_info.get("Protocol", ""),
            packet_info.get("Length", ""),
            packet_info.get("Info", "")
        ))
    
    def pause_sniffer(self):
        self.sniffing = False
        
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "Sniffer paused.\n")
        self.output_text.config(state=tk.DISABLED)
        
        self.start_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.read_button.config(state=tk.NORMAL)
    
    def save_packets(self):
        with open("captured_packets.txt", "w") as f:
            for packet in self.captured_packets:
                packet_info = self.extract_packet_info(packet)
                f.write("Packet Start\n")
                for field, value in packet_info.items():
                    f.write(f"{field}: {value}\n")
                f.write("Packet End\n\n")
    
    def read_packets(self):
        try:
            with open("captured_packets.txt", "r") as f:
                captured_packets = f.read()
            
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, captured_packets)
            self.output_text.config(state=tk.DISABLED)
            
            self.start_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.NORMAL)
            self.read_button.config(state=tk.NORMAL)
        
        except FileNotFoundError:
            messagebox.showerror("Error", "No captured packets file found.")


if __name__ == "__main__":
    root = tk.Tk()
    root.minsize(700, 500)  # Set a minimum size for the window
    app = NetWhisperGUI(root)
    root.mainloop()


