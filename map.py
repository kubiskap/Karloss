import folium
from folium.plugins import MarkerCluster
from folium.plugins import GroupedLayerControl
import random
import re


class Map(object):
    def __init__(self, session_object, packet_types: list):
        self.session_object = session_object
        self.packet_types = packet_types
        self.map_data = self.__prepare_data()
        self.map = None

    def __prepare_data(self):
        def unit_conversion(value):
            match key:
                case 'speed':
                    value = round(value * 0.036, 2)
                case 'latitude' | 'longitude':
                    value = value / 10000000

            return value

        # Isolate all packets matching selected packet types and with data of type dictionary
        selected_packets = [packet for packet in self.session_object.packets if packet.type in self.packet_types
                            and isinstance(packet.data, dict)]

        # Raise an exception if requested packet type is not configured in map_data
        for packet_type in self.packet_types:
            if packet_type not in self.session_object.config['mapConfig'].keys():
                raise Exception(f'Message type "{packet_type}" not configured in config.')

        # Get map data from each selected packet
        map_data = []
        for packet in list(selected_packets):
            # Establish packet value
            pkt_value = {'type': (packet.type, None), 'arrivalTime': (packet.arrival_time, None)}

            # Get config for this packet
            pkt_config = self.session_object.config['mapConfig'][packet.type]['paths']

            # For each parameter configured, find the value under this path
            innerBreak = False
            for key, path in pkt_config.items():

                # If there is path value configured
                if path is not None:

                    # Get value of parameter under this path in current packet
                    value = packet.values.get(path, (None, None))

                    # If anything is found in the packet
                    if value[0] is not None:

                        # If there are no problems with the parameter or the only problem is with named-numbers, proceed
                        if path not in packet.problems.keys():

                            pkt_value[key] = (unit_conversion(value[0]), value[1])

                        # If there are problems, remove the packet
                        else:
                            selected_packets.remove(packet)
                            innerBreak = True
                            break

                    # If the parameter was not found, remove the packet
                    else:
                        selected_packets.remove(packet)
                        innerBreak = True
                        break

                # If parameter has no defined path, raise an error
                else:
                    raise ValueError(f'Path of {key} parameter is not set in mapConfig.')

            if not innerBreak:
                # Append the map packet data to the array
                map_data.append(pkt_value)

        return map_data

    def create(self, group_markers=True):
        def assign_color(used=[]):
            defined = ['red', 'blue', 'green', 'purple', 'orange', 'darkred', 'darkblue', 'darkgreen', 'cadetblue',
                       'pink', 'lightblue', 'lightgreen', 'gray']
            if set(defined) != set(used):
                available_colors = [color for color in defined if color not in used]
                color = available_colors[random.randint(0, len(available_colors) - 1)]
                used.append(color)
            else:
                used = []
                assign_color()
            return used, color

        if self.map_data:
            # Create a Folium map centered at first packet coordinates
            first_packet = self.map_data[0]
            lat, lon = first_packet.get('latitude', 0)[0], first_packet.get('longitude', 0)[0]

            self.map = folium.Map(location=[lat, lon], tiles='OpenStreetMap', zoom_start=12)

            # Add ESRI World Imagery tile layer
            layer_esri = folium.TileLayer(name='ESRI World Imagery',
                                          tiles='https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery'
                                                '/MapServer/tile/{z}/{y}/{x}',
                                          attr='Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS,'
                                               'AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, '
                                               'and the GIS User Community')
            self.map.add_child(layer_esri)

            # Create separate feature groups for each message type and assign them random colors
            used_colors = []

            layers, stationID_layers = {}, {}
            for packet_type in self.packet_types:
                used_colors, color = assign_color(used_colors)

                # Color legend text based on assigned color
                lgd_txt = f'<span style="color: {color};">{packet_type}</span>'

                # Depending on group_markers parameter, create a MarkerCluster/FeatureGroup for message type
                if group_markers:
                    layers[packet_type] = (MarkerCluster(name=lgd_txt, overlay=True, control=True, show=False), color)
                else:
                    layers[packet_type] = (
                        folium.FeatureGroup(name=lgd_txt, overlay=True, control=True, show=False), color)

                layers[packet_type][0].add_to(self.map)
                self.map.add_child(layers[packet_type][0])

                stationIDs = []
                for packet in self.map_data:
                    if packet['stationID'][0] not in stationIDs and packet['type'][0] == packet_type:
                        stationIDs.append(packet['stationID'][0])

                for stationID in stationIDs:
                    stationID_layers[f'{packet_type}_{stationID}'] = folium.plugins.FeatureGroupSubGroup(
                        layers[packet_type][0], name=stationID, show=True)
                    stationID_layers[f'{packet_type}_{stationID}'].add_to(self.map)
                    self.map.add_child(stationID_layers[f'{packet_type}_{stationID}'])

            for packet in self.map_data:
                try:
                    lat, lon = packet['latitude'][0], packet['longitude'][0]
                except KeyError:
                    raise Exception('Packet has no latitude and longitude data')

                config = self.session_object.config['mapConfig'][packet.get("type")[0]]

                # Create popup_text by joining all parameters of packet together in a fashionable way
                popup_text = [f'<b>{re.sub(r"(\w)([A-Z])", r"\1 \2", key).title()}</b>: {value[0]}' for key, value in
                              packet.items()]
                popup_text = '<br>'.join(popup_text)

                # Set default icon
                default_icon = 'envelope'

                # Get parameter which will determine the icon from config, if none found, return default icon
                try:
                    icon_parameter = list(config['icon'].keys())[0]

                    # Try to find icon for parameter
                    icon = config['icon'][icon_parameter][packet[icon_parameter][1]]

                except KeyError:
                    icon = default_icon

                folium.Marker([lat, lon], popup=popup_text, tooltip=packet.get("arrivalTime")[0].strftime(
                    "%d. %m. %Y, %H:%M:%S"), icon=folium.Icon(color=layers[packet['type'][0]][1], icon=icon,prefix='fa')
                              ).add_to(stationID_layers[f'{packet['type'][0]}_{packet['stationID'][0]}'])

            folium.LayerControl(collapsed=False).add_to(self.map)

            # Add GroupedLayerControl
            for packet_type in self.packet_types:
                color = layers[packet_type][1]
                name = f'<span style="color: {color};">{packet_type}</span>_stationID:'
                layer_list = [layer for key, layer in stationID_layers.items() if key.startswith(packet_type)]
                GroupedLayerControl(
                    groups={name: layer_list},
                    collapsed=False,
                    exclusive_groups=False
                ).add_to(self.map)
