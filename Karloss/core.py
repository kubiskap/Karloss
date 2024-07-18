import pyshark
import json
import os
import pickle
import datetime
from operator import add

from .msg import ItsMessage
from .packet import Packet
from .map import Map


class Instance(object):
    def __init__(self, config_location):

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
        try:
            with open(config_location, 'r') as f:
                self.config = json.load(f)
        except json.JSONDecodeError:
            raise Exception('Config syntax invalid. Make sure your json config has valid syntax.')

        self.__ignored_packet_types = ['Malformed', 'Non-C-ITS', 'Unknown C-ITS']

        # Establish ItsMessage object for each message type configured
        self.configured_msgs = {key: ItsMessage(asn_files=value['asnFiles'], msg_name=value['msgName'])
                                for key, value in self.config['msgConfig'].items()}

        # Establish input_file location
        self.input_file = None

        # Establish summary dictionary, packet array and packet type statistics
        self.summary = {}
        self.packets = []
        self.packet_types = {}

        # Create log file for current session
        self.log_file = create_log_file()

        # Initiate state of current session
        self.state = None

        # Display session information
        self.log_message(f'New session started with config: {os.path.abspath(config_location)}')

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

    def __cache_dir(self, subdir):
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
                msg_object = self.configured_msgs.get(pkt.btpb.dstport)

                if msg_object is None:
                    return Packet(msg_type='Unknown C-ITS',
                                  content=None, arrival_time=pkt.sniff_time)
                else:
                    malformed, content = msg_object.decode(encoded=bytes.fromhex(pkt.its_raw.value))

                    # Wrap the entire message into one big container
                    content = {msg_object.msg_name: content}

                    if not malformed:
                        return Packet(msg_type=msg_object.msg_name,
                                      content=content, arrival_time=pkt.sniff_time, asn=msg_object.asn_rebuilt)
                    else:
                        return Packet(msg_type='Malformed',
                                      content=content, arrival_time=pkt.sniff_time, asn=msg_object.asn_rebuilt)
            else:
                return Packet(msg_type='Non-C-ITS',
                              content=None, arrival_time=pkt.sniff_time)

        # Add input_file to method attributes
        self.input_file = input_file

        # Reset packet array
        self.packets = []

        try:
            # Import packets from pcap
            pcap = pyshark.FileCapture(input_file, include_raw=True, use_json=True)

            # Create cache directory
            import_cache_dir = self.__cache_dir('import_cache')

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
                    pkt_object = import_pkt()

                    self.__cache_action(packet_file, 'w', pkt_object)

                    self.packets.append(pkt_object)

            # Update state
            self.state = 'Imported file'

            time_import_end = datetime.datetime.now()
            import_duration = (time_import_end - time_import_start).total_seconds()
            self.log_message(
                f'{idx + 1} packets imported from {os.path.abspath(input_file)}; Import duration: {import_duration:.2f} seconds. '
                f'Total imported packets: {len(self.packets)}')
        finally:
            # Explicitly close the capture to release resources and terminate event loop
            pcap.close()

    def analyse(self, reset_cache=True,
                parameter_expected_value={},
                packet_filter_mode='Undefined',
                filter_packets=[],
                parameter_filter_mode='Undefined',
                filter_parameters=[]):

        # Summarise packet types before the analysis
        self.sum_pkt_types()

        # Catch packet_filter_mode not being 'whitelist'/'blacklist' and filter_packets not being list
        if not isinstance(packet_filter_mode, str) or (
                packet_filter_mode.lower() not in ['blacklist', 'whitelist'] and packet_filter_mode != 'Undefined'):
            raise ValueError(
                '"packet_filter_mode" parameter must be a string with values: "blacklist", "whitelist", or "Undefined"')

        if not isinstance(filter_packets, list) or not all(isinstance(element, str) for element in filter_packets):
            raise ValueError('"filter_packets" parameter must be a list with elements of type string')

        # Handle packet type filtering
        if packet_filter_mode.lower() == 'blacklist':
            self.__ignored_packet_types.extend(
                packet_type for packet_type in filter_packets if packet_type in self.packet_types)
        elif packet_filter_mode.lower() == 'whitelist':
            self.__ignored_packet_types.extend(
                packet_type for packet_type in self.packet_types if packet_type not in filter_packets)

        # Catch parameter_filter_mode not being 'whitelist'/'blacklist'/'Undefined' and filter_parameters not being a list of strings
        if not isinstance(parameter_filter_mode, str) or (parameter_filter_mode.lower() not in ['blacklist',
                                                                                                'whitelist'] and parameter_filter_mode != 'Undefined'):
            raise ValueError(
                '"parameter_filter_mode" parameter must be a string with values: "blacklist", "whitelist", or "Undefined"')

        if not isinstance(filter_parameters, list) or not all(
                isinstance(element, str) for element in filter_parameters):
            raise ValueError('"filter_parameters" parameter must be a list with elements of type string')

        # Catch parameter_expected_value not being a dictionary
        if not isinstance(parameter_expected_value, dict) or not all(
                isinstance(key, str) for key in parameter_expected_value.keys()):
            raise ValueError('"parameter_expected_value" parameter must be a dictionary with keys of type string')

        # Create analysed cache dir
        analysed_cache_dir = self.__cache_dir('analysed_cache')

        # List all files that should be in cache, list if each of the files is present in cache
        cache_files = [os.path.join(analysed_cache_dir, f'packet{idx + 1}.pkl') for idx, pkt in enumerate(self.packets)]
        cache_present = [os.path.isfile(f) for f in cache_files]

        # Only if packets have been imported first
        if self.packets:
            time_analysis_start = datetime.datetime.now()

            # Check if all packets are present in the analysed cache
            if all(cache_present):
                self.log_message('All packets present in analysed cache.')

                if reset_cache:
                    self.log_message('Resetting cache for repeated analysis...')
                    # Delete all files in the analysed cache directory
                    for file in cache_files:
                        os.remove(file)
                    # Reset cache_present
                    cache_present = [os.path.isfile(f) for f in cache_files]
                else:
                    self.log_message('The analysed packet cache has been kept back. Importing results...')

            self.log_message('Starting packet analysis...')
            for idx, file in enumerate(cache_files):

                # Get packet object from array
                pkt = self.packets[idx]

                # If packet is present in analysed cache, replace the current packet with it
                if cache_present[idx]:
                    time_packet_start = datetime.datetime.now()

                    # Replace packet object from array with the one from cache
                    self.packets[idx] = self.__cache_action(file, 'r')

                    time_packet_end = datetime.datetime.now()

                    self.log_message(f'{self.packets[idx].type} packet {idx + 1}/{len(self.packets)} loaded from'
                                     f' analysed cache in '
                                     f'{(time_packet_end - time_packet_start).total_seconds()} seconds.')

                # If not present in analysed cache, analyse it and save it into the cache
                elif not cache_present[idx]:
                    if pkt.type not in self.__ignored_packet_types:
                        time_packet_start = datetime.datetime.now()

                        # Analyse packet
                        pkt.analyse_packet(parameter_expected_value=parameter_expected_value,
                                           filter_mode=parameter_filter_mode, filter_parameters=filter_parameters)

                        time_packet_end = datetime.datetime.now()

                        # Save packet into cache after analysis
                        self.__cache_action(file, 'w', pkt)

                        self.log_message(
                            f'{pkt.type} packet {idx + 1}/{len(self.packets)} analysed in '
                            f'{(time_packet_end - time_packet_start).total_seconds():.1f} seconds.')
                    else:
                        # Save packet into analysed cache to know its' analysis was skipped
                        self.__cache_action(file, 'w', pkt)

                        self.log_message(f'Skipping {pkt.type} packet {idx + 1}/{len(self.packets)}.')

            # Update state
            self.state = 'Analysis complete'

            time_analysis_end = datetime.datetime.now()
            self.log_message('Analysis complete.'
                             f' Duration: {(time_analysis_end - time_analysis_start).total_seconds() / 60} min;'
                             f' Packets analysed: {len(self.packets)}')

        else:
            self.log_message('You need to import the packets first before analysis.')

    def create_summary(self):
        """
        Method used to take individual packet summaries and sum them into the analysis summary.
        """
        # Clear previous content of summary attribute
        self.summary = {}

        for packet in self.packets:
            default_val = [0, 0, 0]
            ps = packet.summary
            s = self.summary

            self.summary = {k: list(map(add, ps.get(k, default_val), s.get(k, default_val))) for k in
                            set(ps) | set(s)}

    def sum_pkt_types(self):
        """
        Method used to summarize packet types present in the file.
        """

        def pkt_types_algorithm():
            if packet.type in self.packet_types:

                if packet.state in self.packet_types[packet.type]:
                    self.packet_types[packet.type][packet.state]['num'] += 1

                    if packet.problems:
                        warnings, errors = [], []

                        for parameter, value in packet.problems.items():
                            if value['Warnings']:
                                warnings.append(parameter)
                            if value['Errors']:
                                errors.append(parameter)

                        idx_val = {'warningParams': warnings, 'errorParams': errors}
                    else:
                        idx_val = {'warningParams': None, 'errorParams': None}

                    self.packet_types[packet.type][packet.state]['idx'][idx + 1] = idx_val
                else:
                    self.packet_types[packet.type][packet.state] = {'num': 0, 'idx': {}}
                    pkt_types_algorithm()

            else:
                self.packet_types[packet.type] = {}
                pkt_types_algorithm()

        # Clear previous content of packet_types attribute:
        self.packet_types = {}

        for idx, packet in enumerate(self.packets):
            pkt_types_algorithm()

    def output_results(self, output_location):

        if self.state == 'Analysis complete':

            # Generate final statistics
            self.create_summary()
            self.sum_pkt_types()

            # Create folder in output_location based on session name (taken from log_file)
            output_path = os.path.join(output_location, os.path.splitext(os.path.basename(self.log_file))[0])
            if not os.path.exists(output_path):
                os.makedirs(output_path)

            # Generate summary.json
            with open(os.path.join(output_path, 'summary.json'), 'w') as f:
                json.dump(self.summary, f, indent=4, sort_keys=True, default=str)

            # Generate pkt_types.json
            with open(os.path.join(output_path, 'pkt_types.json'), 'w') as f:
                json.dump(self.packet_types, f, indent=4, sort_keys=True, default=str)

            # Generate output for each analysed packet
            packets_path = os.path.join(output_path, 'packets')
            if not os.path.exists(packets_path):
                os.makedirs(packets_path)

            for idx, packet in enumerate(self.packets):

                # Merge packet.values and packet.analysed into one dict
                parameters = {}

                for parameter, analysed_val in sorted(packet.analysed.items()):
                    values_val = packet.values.get(parameter, ('Not found', None))

                    parameters[parameter] = {
                        'value': values_val[0],
                        'namedNum': values_val[1],
                        'state': analysed_val[0],
                        'problems': analysed_val[1]
                    }

                # Join desired packet parameters into one dict
                json_packet = {
                    'arrivalTime': packet.arrival_time,
                    'type': packet.type,
                    'state': packet.state,
                    'problems': dict(sorted(packet.problems.items())),
                    'parameters': parameters
                }
                with open(os.path.join(packets_path, f'packet{idx + 1}.json'), 'w') as f:
                    json.dump(json_packet, f, indent=4, sort_keys=False, default=str)

            # Add a message to the log
            self.log_message(f'Results successfully exported to: {output_path}')

    def plot_map(self, packet_types, output_location, group_markers=True):
        if self.state == 'Analysis complete':
            self.log_message('Plotting map...')

            # Initiate map object
            map_object = Map(self, packet_types)

            # Create map
            map_object.create(group_markers)

            # Save map
            if os.path.isdir(output_location):
                output_location = os.path.join(output_location, os.path.splitext(os.path.basename(self.log_file))[0] + '.html')
            map_object.map.save(output_location)

            self.log_message(f'Map successfully plotted to {output_location}')
