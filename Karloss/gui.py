import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import sys
import datetime
import threading
from io import StringIO
import json

from .core import Instance


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

        # Frame to hold buttons
        button_frame = tk.Frame(root)
        button_frame.pack(padx=5, pady=10)

        self.analyze_button = tk.Button(
            button_frame, text="Analyze Packets", command=self.analyze_packets
        )
        self.analyze_button.pack(side=tk.LEFT, padx=5)

        self.export_button = tk.Button(
            button_frame, text="Export Results", command=self.export_results, state=tk.DISABLED
        )
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.plot_map_button = tk.Button(
            button_frame, text="Plot Map", command=self.plot_map, state=tk.DISABLED
        )
        self.plot_map_button.pack(side=tk.LEFT, padx=5)

        # Log window to display import and analysis progress
        self.log_text = scrolledtext.ScrolledText(root, width=80, height=20, wrap=tk.WORD)
        self.log_text.pack(padx=5, pady=10)

        # Display import information in the log text window and log file
        self.gui_log_message(f"{len(packet_handler.packets)} packets imported from {self.config_file};"
                             f" Import duration: {import_duration:.2f} seconds.")

    def analyze_packets(self):
        # Disable button during analysis
        self.analyze_button.config(state=tk.DISABLED)
        threading.Thread(target=self.perform_analysis).start()

    def perform_analysis(self):
        # Disable Export and Plot button during analysis
        self.export_button.config(state=tk.DISABLED)
        self.plot_map_button.config(state=tk.DISABLED)

        # Redirect stdout to the log text widget
        sys.stdout = WindowStream(self.log_text)

        try:
            # Perform packet analysis
            self.packet_handler.analyse()

            # Enable Export and Plot button after analysis is complete
            self.export_button.config(state=tk.NORMAL)
            self.plot_map_button.config(state=tk.NORMAL)
        except Exception as e:
            # Print any exceptions to the redirected stdout
            print(f"Error during analysis: {str(e)}")
        finally:
            # Restore sys.stdout
            sys.stdout = sys.__stdout__

    def export_results(self):
        # Redirect stdout to the log text widget
        sys.stdout = WindowStream(self.log_text)

        # Prompt user to select directory for exporting results
        export_dir = filedialog.askdirectory()
        if export_dir:
            # Call method to export results from PacketAnalyser
            self.packet_handler.output_results(export_dir)

        # Restore sys.stdout
        sys.stdout = sys.__stdout__

    def plot_map(self):
        def map_configuration_window(options):
            selected_types = []

            # Create a new Toplevel window for the multiselect dialog
            dialog = tk.Toplevel(self.root)
            dialog.title('Configure Map Plot')

            # Label to display instructions to select message types
            label = ttk.Label(dialog, text='Message Types')
            label.pack(padx=10, pady=10)

            # Create Checkbuttons for each option
            checkbuttons = []
            for option in options:
                var = tk.BooleanVar(value=False)
                checkbutton = ttk.Checkbutton(dialog, text=option, variable=var)
                checkbutton.pack(anchor=tk.W, padx=10, pady=5)
                checkbuttons.append((option, var))

            # Label to display instructions to if MarkerCluster is wanted
            label = ttk.Label(dialog, text='Plot Configuration')
            label.pack(padx=10, pady=10)

            group_markers = tk.BooleanVar(value=True)
            group_markers_checkbutton = ttk.Checkbutton(dialog, text='Group markers', variable=group_markers)
            group_markers_checkbutton.pack(anchor=tk.W, padx=10, pady=5)

            # Function to handle dialog close and return selected types
            def close_dialog():
                nonlocal selected_types
                selected_types = [option for option, var in checkbuttons if var.get()]
                dialog.destroy()

            # Button to confirm and close dialog
            confirm_button = ttk.Button(dialog, text="Confirm", command=close_dialog)
            confirm_button.pack(pady=10)

            # Set modal behavior for the dialog (blocks interaction with parent window)
            dialog.transient(self.root)
            dialog.grab_set()
            self.root.wait_window(dialog)

            return selected_types, group_markers.get()

        # Redirect stdout to the log text widget
        sys.stdout = WindowStream(self.log_text)

        # Read configured message types from config
        with open(self.config_file, 'r') as f:
            config = json.load(f)
        types_configured = list(config.get('mapConfig', {}).keys())

        # Prompt user to select types to plot from configured types
        types_selected, markercluster = map_configuration_window(types_configured)

        # If there are some message types selected
        if types_selected:
            # Prompt user to choose a location to save the map HTML file
            save_path = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML File", "*.html")],
                title="Save Map HTML File",
            )

            if save_path:
                self.packet_handler.plot_map(
                    packet_types=types_selected, output_location=save_path, group_markers=markercluster)

    def gui_log_message(self, message):
        # Get current date and time
        timestamp = datetime.datetime.now().strftime("[%d-%m-%Y %H:%M:%S]")

        # Format the log message with timestamp
        formatted_message = f"{timestamp} {message}"

        # Append the message to the log text window
        self.log_text.insert(tk.END, formatted_message + "\n")
        self.log_text.see(tk.END)  # Scroll to the end of the log
