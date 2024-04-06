import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter.ttk import Progressbar
from core import Packets
import json
import datetime
import threading


class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")

        # Variables to hold file paths
        self.config_file_path = tk.StringVar()
        self.pcap_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()

        # Create GUI elements
        tk.Label(root, text="Configuration File:").grid(row=0, column=0, padx=5, pady=5)
        self.config_entry = tk.Entry(root, textvariable=self.config_file_path, width=50)
        self.config_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(root, text="Browse", command=self.browse_config_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(root, text="PCAP File:").grid(row=1, column=0, padx=5, pady=5)
        self.pcap_entry = tk.Entry(root, textvariable=self.pcap_file_path, width=50)
        self.pcap_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(root, text="Browse", command=self.browse_pcap_file).grid(row=1, column=2, padx=5, pady=5)

        self.progressbar = Progressbar(root, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progressbar.grid(row=2, column=0, columnspan=3, padx=5, pady=10)

        tk.Button(root, text="Import and Analyze Packets", command=self.start_import_and_analyze).grid(row=3, column=1,
                                                                                                      padx=5,
                                                                                                      pady=10)

        tk.Label(root, text="Output File:").grid(row=4, column=0, padx=5, pady=5)
        self.output_entry = tk.Entry(root, textvariable=self.output_file_path, width=50)
        self.output_entry.grid(row=4, column=1, padx=5, pady=5)
        tk.Button(root, text="Save Output", command=self.save_output).grid(row=4, column=2, padx=5, pady=5)

        # Log window to display analysis progress
        self.log_text = scrolledtext.ScrolledText(root, width=80, height=20, wrap=tk.WORD)
        self.log_text.grid(row=5, column=0, columnspan=3, padx=5, pady=10)

        # Initialize Packets object
        self.packet_handler = None
        self.total_packets = 0
        self.current_packet_index = 0

    def browse_config_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if file_path:
            self.config_file_path.set(file_path)

    def browse_pcap_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            self.pcap_file_path.set(file_path)

    def start_import_and_analyze(self):
        config_file = self.config_file_path.get()
        pcap_file = self.pcap_file_path.get()

        if config_file and pcap_file:
            # Disable button during import and analysis
            self.root.update()
            self.disable_ui()

            # Start import and analysis in a separate thread
            threading.Thread(target=self.import_and_analyze_thread, args=(config_file, pcap_file)).start()

    def import_and_analyze_thread(self, config_file, pcap_file):
        start_import_time = datetime.datetime.now()

        try:
            import asyncio

            # Set up event loop explicitly for pyshark within the new thread
            asyncio.set_event_loop(asyncio.new_event_loop())

            # Initialize Packets object with the specified config file
            self.packet_handler = Packets(config_location=config_file)

            # Import packets from the specified PCAP file
            self.packet_handler.import_file(pcap_file)

            end_import_time = datetime.datetime.now()
            import_duration = (end_import_time - start_import_time).total_seconds()

            # Get total number of packets
            self.total_packets = len(self.packet_handler.packets)
            self.current_packet_index = 0

            # Update progress bar settings
            self.progressbar['maximum'] = self.total_packets
            self.progressbar['value'] = 0

            # Log import statistics
            import_stats_message = f"Packets imported: {self.total_packets}, Import duration: {import_duration} seconds."
            self.log_text.insert(tk.END, import_stats_message + "\n")

            # Start analyzing packets
            self.analyze_packets()

        except Exception as e:
            self.log_text.insert(tk.END, f"Error during import and analysis: {str(e)}\n")

        finally:
            # Re-enable UI after analysis is complete or on error
            self.enable_ui()
            messagebox.showinfo("Analysis Complete", "All packets have been analyzed.")

    def analyze_packets(self):
        while self.current_packet_index < self.total_packets:
            # Analyze the next packet
            packet = self.packet_handler.packets[self.current_packet_index]

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
                log_message = f"{packet.type} packet {self.current_packet_index + 1}/{self.total_packets} analyzed. " \
                              f"Analysis duration: {analysis_duration} seconds."
                self.log_text.insert(tk.END, log_message + "\n")
                self.log_text.see(tk.END)  # Scroll to the end of the log

            # Update progress bar
            self.progressbar['value'] = self.current_packet_index + 1
            self.current_packet_index += 1

        # Re-enable UI after analysis is complete
        self.enable_ui()
        messagebox.showinfo("Analysis Complete", "All packets have been analyzed.")

    def save_output(self):
        output_file = self.output_file_path.get()

        if output_file and self.packet_handler:
            # Prepare output dictionary with data_analysed and summary
            output_data = {
                'data_analysed': [pkt.data_analysed for pkt in self.packet_handler.packets],
                'summary': self.packet_handler.summary
            }

            # Write output data to JSON file
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=4)

            messagebox.showinfo("Success", f"Analysis results saved to {output_file}!")

    def disable_ui(self):
        # Disable buttons and entry fields during import and analysis
        for widget in (self.config_entry, self.pcap_entry, self.output_entry):
            widget.config(state=tk.DISABLED)
        for button in (self.root.winfo_children()):
            if isinstance(button, tk.Button) and button != self.root:
                button.config(state=tk.DISABLED)

    def enable_ui(self):
        # Enable buttons and entry fields after import and analysis is complete
        for widget in (self.config_entry, self.pcap_entry, self.output_entry):
            widget.config(state=tk.NORMAL)
        for button in (self.root.winfo_children()):
            if isinstance(button, tk.Button) and button != self.root:
                button.config(state=tk.NORMAL)


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
