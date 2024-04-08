import pyshark
import json
import os
import pickle
import datetime
from operator import add

from msg import ItsMessage
from packet import Packet


class Packets(object):
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
        self.log_file_name = create_log_file()

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
        with open(self.log_file_name, "a") as log_file:
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

        # Import packets from pcap
        pcap = pyshark.FileCapture(input_file, include_raw=True, use_json=True)

        # Clear out packet_array
        self.packets = []

        # Create cache directory
        import_cache_dir = self.cache_dir('import_cache')

        for idx, pkt in enumerate(pcap):

            # Packet file path used for cache
            packet_file = os.path.join(import_cache_dir, f'packet{idx + 1}.pkl')

            # If packet is in cache dir, load it from there instead of importing it again
            if os.path.exists(packet_file):

                with open(packet_file, 'rb') as f:
                    pickle_pkt = pickle.load(f)

                self.packets.append(pickle_pkt)

            # If packet is not in cache dir, import and save it
            else:
                pkt_content, pkt_type = import_pkt()
                pkt_object = Packet(msg_type=pkt_type, content=pkt_content)

                with open(packet_file, 'wb') as f:
                    pickle.dump(pkt_object, f, pickle.HIGHEST_PROTOCOL)

                self.packets.append(pkt_object)

    def analyse_packets(self):

        def add_pkt_summary():
            default_val = [0, 0, 0]
            ps = pkt.pkt_summary
            s = self.summary

            self.summary = {k: list(map(add, ps.get(k, default_val), s.get(k, default_val))) for k in set(ps) | set(s)}

        # Only if packets have been imported first
        if self.packets:
            print('Starting packet analysis...')
            time_analysis_start = datetime.datetime.now()

            for idx, pkt in enumerate(self.packets):
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
                    print(
                        f'{pkt.type} packet {idx + 1}/{len(self.packets)} analysed in '
                        f'{(time_packet_end - time_packet_start).total_seconds()} seconds.')
                else:
                    time_packet_end = datetime.datetime.now()
                    print(
                        f'Packet {idx + 1}/{len(self.packets)} was not analysed '
                        f'({(time_packet_end - time_packet_start).total_seconds()} s) -- {pkt.type}.')

            time_analysis_end = datetime.datetime.now()
            print('-----------------------------------\n'
                  f'Duration: {(time_analysis_end - time_analysis_start).total_seconds() / 60} min;'
                  f'Packets analysed: {len(self.packets)}')

        else:
            print('You need to import the packets first.')
