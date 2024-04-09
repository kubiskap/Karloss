import tkinter as tk
from tkinter import filedialog, scrolledtext
import sys
from core import PacketAnalyser
import datetime
import threading
from io import StringIO


class WindowStream(StringIO):
    def __init__(self, text_widget):
        self.text_widget = text_widget
        super().__init__()

    def write(self, data):
        self.text_widget.insert(tk.END, data)
        self.text_widget.see(tk.END)  # Auto-scroll to the end of the text
        super().write(data)


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
            # Initialize PacketAnalyser object with the specified config file
            packet_handler = PacketAnalyser(config_location=config_file)

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
        tk.Label(root, text=f"Configuration File: {config_file}").pack(padx=5, pady=5)
        tk.Label(root, text=f"PCAP File: {pcap_file}").pack(padx=5, pady=5)

        tk.Button(root, text="Analyze Packets", command=self.analyze_packets).pack(padx=5, pady=10)

        # Log window to display import and analysis progress
        self.log_text = scrolledtext.ScrolledText(root, width=80, height=20, wrap=tk.WORD)
        self.log_text.pack(padx=5, pady=10)

        # Display import information in the log text window and log file
        self.gui_log_message(f"{len(packet_handler.packets)} packets imported from {self.config_file};"
                             f" Import duration: {import_duration:.2f} seconds.")

    def analyze_packets(self):
        # Disable button during analysis
        self.root.update_idletasks()  # Ensure button state is updated visually
        threading.Thread(target=self.perform_analysis).start()

    def perform_analysis(self):
        # Redirect stdout to the log text widget
        sys.stdout = WindowStream(self.log_text)

        try:
            # Perform packet analysis
            self.packet_handler.analyse()
        except Exception as e:
            # Print any exceptions to the redirected stdout
            print(f"Error during analysis: {str(e)}")
        finally:
            # Restore sys.stdout
            sys.stdout = sys.__stdout__

            # Enable UI after analysis
            self.root.after(0, self.enable_ui)

    def disable_ui(self):
        # Disable the Analyze Packets button
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Button) and widget["text"] == "Analyze Packets":
                widget.config(state=tk.DISABLED)

    def enable_ui(self):
        # Enable the Analyze Packets button
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Button) and widget["text"] == "Analyze Packets":
                widget.config(state=tk.NORMAL)

    def gui_log_message(self, message):
        # Get current date and time
        timestamp = datetime.datetime.now().strftime("[%d-%m-%Y %H:%M:%S]")

        # Format the log message with timestamp
        formatted_message = f"{timestamp} {message}"

        # Append the message to the log text window
        self.log_text.insert(tk.END, formatted_message + "\n")
        self.log_text.see(tk.END)  # Scroll to the end of the log


if __name__ == "__main__":
    # Launch the configuration window
    config_root = tk.Tk()
    config_app = ConfigurationWindow(config_root)
    config_root.mainloop()
