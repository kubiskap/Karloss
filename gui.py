import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter.ttk import Progressbar
from core import Packets
import datetime
import threading
import os
import pickle

class ConfigurationWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Configuration")

        # Variables to hold file paths
        self.config_file_path = tk.StringVar()
        self.pcap_file_path = tk.StringVar()

        # Create GUI elements for configuration window
        tk.Label(root, text="Select Configuration File:").grid(row=0, column=0, padx=5, pady=5)
        self.config_entry = tk.Entry(root, textvariable=self.config_file_path, width=50)
        self.config_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(root, text="Browse", command=self.browse_config_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(root, text="Select PCAP File:").grid(row=1, column=0, padx=5, pady=5)
        self.pcap_entry = tk.Entry(root, textvariable=self.pcap_file_path, width=50)
        self.pcap_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(root, text="Browse", command=self.browse_pcap_file).grid(row=1, column=2, padx=5, pady=5)

        tk.Button(root, text="Accept Config", command=self.accept_config).grid(row=2, column=1, padx=5, pady=10)

    def browse_config_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if file_path:
            self.config_file_path.set(file_path)

    def browse_pcap_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            self.pcap_file_path.set(file_path)

    def accept_config(self):
        config_file = self.config_file_path.get()
        pcap_file = self.pcap_file_path.get()

        if config_file and pcap_file:
            # Initialize Packets object with the specified config file
            packet_handler = Packets(config_location=config_file)

            # Import packets from the specified PCAP file
            start_import_time = datetime.datetime.now()
            packet_handler.import_file(pcap_file)
            end_import_time = datetime.datetime.now()

            # Calculate import duration
            import_duration = (end_import_time - start_import_time).total_seconds()

            # Close the configuration window
            self.root.destroy()

            # Launch the main GUI window with the packet handler and import duration
            root = tk.Tk()
            app = PacketAnalyzerApp(root, config_file, pcap_file, packet_handler, import_duration)
            root.mainloop()


class PacketAnalyzerApp:
    def __init__(self, root, config_file, pcap_file, packet_handler, import_duration):
        self.root = root
        self.root.title("Packet Analyzer")

        self.config_file = config_file
        self.pcap_file = pcap_file
        self.packet_handler = packet_handler
        self.import_duration = import_duration

        # Create GUI elements for main window
        tk.Label(root, text=f"Configuration File: {config_file}").grid(row=0, column=0, padx=5, pady=5)
        tk.Label(root, text=f"PCAP File: {pcap_file}").grid(row=1, column=0, padx=5, pady=5)

        self.progressbar = Progressbar(root, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progressbar.grid(row=2, column=0, columnspan=2, padx=5, pady=10)

        tk.Button(root, text="Analyze Packets", command=self.analyze_packets).grid(row=3, column=0, padx=5, pady=10)

        # Log window to display import and analysis progress
        self.log_text = scrolledtext.ScrolledText(root, width=80, height=20, wrap=tk.WORD)
        self.log_text.grid(row=4, column=0, columnspan=2, padx=5, pady=10)

        # Create a log file for the current session
        self.log_file_name = self.create_log_file()

        # Display import information in the log text window and log file
        self.log_message(f"Packets imported: {len(packet_handler.packets)}, Import duration: {import_duration:.2f} seconds.")

    def analyze_packets(self):
        # Disable button during analysis
        self.root.update()
        self.disable_ui()

        # Start analyzing packets in a separate thread
        threading.Thread(target=self.analyze_packets_thread).start()

    def analyze_packets_thread(self):
        total_packets = len(self.packet_handler.packets)
        current_packet_index = 0

        # Get the name of the input file without the path and extension
        subfolder_name = os.path.basename(self.pcap_file)

        # Create the directory for analysed packet cache if it doesn't exist
        cache_dir = os.path.join('cache', subfolder_name, 'analysed_cache')
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        # Check if all packets have been analysed by comparing cache files with expected packet count
        cache_files = os.listdir(cache_dir)
        if len(cache_files) == total_packets:
            # All packets have been previously analysed, reset cache and perform full analysis
            self.reset_cache(cache_dir)
            self.log_message("Resetting cache for full analysis...")
        else:
            # Resume analysis from the last analysed packet index
            current_packet_index = len(cache_files)
            self.log_message(f"Resuming analysis from packet {current_packet_index + 1}...")

        while current_packet_index < total_packets:
            # Analyze the next packet
            packet = self.packet_handler.packets[current_packet_index]

            # Get asn_rebuilt for packet type
            pkt_asn = [msg.asn_rebuilt for msg in self.packet_handler.configured_msgs.values() if
                       packet.type == msg.msg_name]

            # If ASN for this message type has been found, proceed with analysis
            if pkt_asn:
                start_analysis_time = datetime.datetime.now()

                # Analyze packet
                packet.analyse_packet(pkt_asn[0])

                end_analysis_time = datetime.datetime.now()
                analysis_duration = (end_analysis_time - start_analysis_time).total_seconds()

                # Log analysis progress
                self.log_message(f"{packet.type} packet {current_packet_index + 1}/{total_packets} analyzed. Analysis duration: {analysis_duration:.2f} seconds.")

                # Cache the analysed packet
                packet_cache_file = os.path.join(cache_dir, f'packet{current_packet_index + 1}.pkl')
                with open(packet_cache_file, 'wb') as f:
                    pickle.dump(packet, f, pickle.HIGHEST_PROTOCOL)

            # Update progress bar
            self.progressbar['value'] = current_packet_index + 1
            current_packet_index += 1

        # Re-enable UI after analysis is complete
        self.enable_ui()
        self.log_message("Analysis Complete")

    def reset_cache(self, cache_dir):
        # Delete all files in the analysed cache directory
        for file in os.listdir(cache_dir):
            file_path = os.path.join(cache_dir, file)
            os.remove(file_path)

    def disable_ui(self):
        # Disable button during analysis
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Button):
                widget.config(state=tk.DISABLED)

    def enable_ui(self):
        # Enable button after analysis is complete
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Button):
                widget.config(state=tk.NORMAL)

    def create_log_file(self):
        # Create 'log' folder if it doesn't exist
        if not os.path.exists("log"):
            os.makedirs("log")

        # Generate a log file name based on current date and time
        timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        log_file_name = f"log/session_{timestamp}.log"

        # Return the log file name
        return log_file_name

    def log_message(self, message):
        # Get current date and time
        timestamp = datetime.datetime.now().strftime("[%d-%m-%Y %H:%M:%S]")

        # Format the log message with timestamp
        formatted_message = f"{timestamp} {message}"

        # Append the message to the log text window
        self.log_text.insert(tk.END, formatted_message + "\n")
        self.log_text.see(tk.END)  # Scroll to the end of the log

        # Append the message to the log file
        with open(self.log_file_name, "a") as log_file:
            log_file.write(formatted_message + "\n")


if __name__ == "__main__":
    # Launch the configuration window first
    config_root = tk.Tk()
    config_app = ConfigurationWindow(config_root)
    config_root.mainloop()
