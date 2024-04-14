import folium
import jsonpath_ng


class Map(object):
    def __init__(self, packet_array: list, packet_types: list, config: dict):

        # Isolate all packets matching selected packet types
        selected_packets = [packet for packet in packet_array if packet.type in packet_types]

        # Establish map data location for each packet type defined
        self.map_data = config['mapData']

        # Raise an exception if requested packet type is not configured in map_data
        for packet_type in packet_types:
            if packet_type not in self.map_data.keys():
                raise Exception(f'Message type "{packet_type}" not configured in confi.')

        # Get map data from each selected packet
        self.map_packets = []
        for packet in selected_packets:
            # Establish packet value
            pkt_value = {'type': packet.type, 'arrivalTime': packet.arrival_time}

            # Get config for this packet
            pkt_config = self.map_data[packet.type]

            # For each parameter configured, find the value under this path
            for key, path in pkt_config.items():
                if (path not in packet.pkt_problems) or (
                        'Value not in named-numbers.' in packet.pkt_problems.get(path, [[], []])[0]):
                    matches = jsonpath_ng.parse("$." + path).find(packet.data)
                    pkt_value[key] = list(matches[0].value.keys())[0]

                # Append the map packet data to the array
                self.map_packets.append(pkt_value)


