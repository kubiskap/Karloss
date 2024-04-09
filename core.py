import pyshark
import json
import os
import pickle
import datetime
from operator import add

from msg import ItsMessage
from packet import Packet


class PacketAnalyser(object):
    def __init__(self, config_location='./config.json'):

        def create_log_file():
            # Create 'log' folder in root if it doesn't exist
            if not os.path.exists("log"):
                os.makedirs("log")

            # Generate a log file name based on current date and time
            timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
            log_file_name = f"log/session_{timestamp}.log"

            # Return the log file name
            return log_file_name

        # Open config
        with open(config_location, 'r') as f:
            config = json.load(f)

        # Establish ItsMessage object for each message type configured
        self.configured_msgs = {key: ItsMessage(asn_files=value['asnFiles'], msg_name=value['msgName'])
                                for key, value in config['msgPorts'].items()}

        # Establish input_file location
        self.input_file = None

        # Establish summary dictionary and packet array
        self.summary = {}
        self.packets = []

        # Create log file for current session
        self.log_file = create_log_file()

        # Display session information
        self.log_message(f'New session started with config: {config_location}')

    @staticmethod
    def __cache_action(file_path, action, cache_object=None):
        match action:
            case 'w':
                with open(file_path, 'wb') as f:
                    pickle.dump(cache_object, f, pickle.HIGHEST_PROTOCOL)
            case 'r':
                with open(file_path, 'rb') as f:
                    cache_object = pickle.load(f)
                return cache_object

    def cache_dir(self, subdir):
        # Get the name of the input file without the path and extension
        subfolder_name = os.path.basename(self.input_file)

        # Create the directory for cache if it doesn't exist
        cache_dir = os.path.join('cache', subfolder_name, subdir)
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        return cache_dir

    def log_message(self, message):
        # Get current date and time
        timestamp = datetime.datetime.now().strftime("[%d-%m-%Y %H:%M:%S]")

        # Format the log message with timestamp
        formatted_message = f"{timestamp} {message}"

        # Append the message to the log file
        with open(self.log_file, "a") as log_file:
            log_file.write(formatted_message + "\n")

        # Print log entry
        print(formatted_message)

        # Return message as variable for use in GUI
        return formatted_message

    def import_file(self, input_file):
        """
        Method to decode all packets in "input_file" and stack them into an array of dictionaries.

        It recognizes if a packet is malformed or is not an ITS packet and adds this information into the list.
        """

        def import_pkt():
            """
            Distinguish between C-ITS, other packets, and malformed packets and return packet data and packet type.
            """
            if 'ITS' in str(pkt.layers):
                if 'MALFORMED' in str(pkt.layers):
                    return None, 'Malformed packet'
                else:
                    try:
                        msg_object = self.configured_msgs.get(pkt.btpb.dstport)
                    except KeyError:
                        return None, 'Unconfigured C-ITS message'
                    else:
                        return msg_object.decode(bytes.fromhex(pkt.its_raw.value)), msg_object.msg_name
            else:
                return None, 'Non-C-ITS packet'

        # Add input_file to method attributes
        self.input_file = input_file

        # Reset packet array
        self.packets = []

        try:
            # Import packets from pcap
            pcap = pyshark.FileCapture(input_file, include_raw=True, use_json=True)

            # Create cache directory
            import_cache_dir = self.cache_dir('import_cache')

            time_import_start = datetime.datetime.now()

            for idx, pkt in enumerate(pcap):

                # Packet file path used for cache
                packet_file = os.path.join(import_cache_dir, f'packet{idx + 1}.pkl')

                # If packet is in cache dir, load it from there instead of importing it again
                if os.path.exists(packet_file):
                    loaded_pkt = self.__cache_action(packet_file, 'r')
                    self.packets.append(loaded_pkt)

                # If packet is not in cache dir, import and save it
                else:
                    pkt_content, pkt_type = import_pkt()
                    pkt_object = Packet(msg_type=pkt_type, content=pkt_content)

                    self.__cache_action(packet_file, 'w', pkt_object)

                    self.packets.append(pkt_object)

            time_import_end = datetime.datetime.now()
            import_duration = (time_import_end - time_import_start).total_seconds()
            self.log_message(
                f'{idx + 1} packets imported from {input_file}; Import duration: {import_duration:.2f} seconds. '
                f'Total imported packets: {len(self.packets)}')
        finally:
            # Explicitly close the capture to release resources and terminate event loop
            pcap.close()

    def analyse_packets(self):

        def add_pkt_summary():
            default_val = [0, 0, 0]
            ps = pkt.pkt_summary
            s = self.summary

            self.summary = {k: list(map(add, ps.get(k, default_val), s.get(k, default_val))) for k in set(ps) | set(s)}

        # Create analysed cache dir
        analysed_cache_dir = self.cache_dir('analysed_cache')

        # List all files that should be in cache, list if each of the files is present in cache
        cache_files = [os.path.join(analysed_cache_dir, f'packet{idx + 1}.pkl') for idx, pkt in enumerate(self.packets)]
        cache_present = [os.path.isfile(f) for f in cache_files]

        # Only if packets have been imported first
        if self.packets:
            time_analysis_start = datetime.datetime.now()

            # Check if all packets are present in the analysed cache
            if all(cache_present):
                self.log_message('All packets present in analysed cache. Resetting cache for repeated analysis...')

                # Delete all files in the analysed cache directory
                for file in cache_files:
                    os.remove(file)

            self.log_message('Starting packet analysis...')
            for idx, file in enumerate(cache_files):

                # Get packet object from array
                pkt = self.packets[idx]

                # If packet is present in analysed cache, replace the current packet with it
                if cache_present[idx]:
                    time_packet_start = datetime.datetime.now()

                    # Replace packet object from array with the one from cache
                    self.packets[idx] = self.__cache_action(file, 'r')

                    # Add pkt_summary of the packet into the big summary
                    add_pkt_summary()

                    time_packet_end = datetime.datetime.now()

                    self.log_message(f'{self.packets[idx].type} packet {idx + 1}/{len(self.packets)} loaded from'
                                     f' analysed cache in '
                                     f'{(time_packet_end - time_packet_start).total_seconds()} seconds.')

                # If not present in analysed cache, analyse it and save it into the cache
                elif not cache_present[idx]:
                    time_packet_start = datetime.datetime.now()

                    # Get asn_rebuilt for packet type
                    pkt_asn = [msg.asn_rebuilt for msg in self.configured_msgs.values() if pkt.type == msg.msg_name]

                    # If ASN for this message type has been found, proceed with analysis
                    if pkt_asn:
                        # Analyse packet
                        pkt.analyse_packet(pkt_asn[0])

                        # Add pkt_summary of the packet into the big summary
                        add_pkt_summary()

                        time_packet_end = datetime.datetime.now()

                        # Save packet into cache after analysis
                        self.__cache_action(file, 'w', pkt)

                        self.log_message(
                                f'{pkt.type} packet {idx + 1}/{len(self.packets)} analysed in '
                                f'{(time_packet_end - time_packet_start).total_seconds()} seconds.')
                    else:
                        time_packet_end = datetime.datetime.now()

                        # Save not supported packet into analysed cache
                        self.__cache_action(file, 'w', pkt)

                        self.log_message(
                            f'Packet {idx + 1}/{len(self.packets)} was not analysed '
                            f'({(time_packet_end - time_packet_start).total_seconds()} s) -- {pkt.type}.')

            time_analysis_end = datetime.datetime.now()
            self.log_message('Analysis complete.'
                             f'Duration: {(time_analysis_end - time_analysis_start).total_seconds() / 60} min;'
                             f' Packets analysed: {len(self.packets)}')

        else:
            self.log_message('You need to import the packets first before analysis.')
