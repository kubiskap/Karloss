import folium
from folium.plugins import MarkerCluster
from folium.plugins import GroupedLayerControl
import jsonpath_ng
import random


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
            if packet_type not in self.session_object.config['mapData'].keys():
                raise Exception(f'Message type "{packet_type}" not configured in config.')

        # Get map data from each selected packet
        map_data = []
        for packet in selected_packets:
            # Establish packet value
            pkt_value = {'type': packet.type, 'arrivalTime': packet.arrival_time}

            # Get config for this packet
            pkt_config = self.session_object.config['mapData'][packet.type]

            # For each parameter configured, find the value under this path
            for key, path in pkt_config.items():

                # If there is path value configured
                if path is not None:
                    # Get content of current packet under this path
                    matches = jsonpath_ng.parse("$." + path).find(packet.data)

                    # If anything is found in the packet
                    if matches:

                        # If there are no problems with the parameter or the only problem is with named-numbers, proceed
                        if (path not in packet.pkt_problems.keys()) or (
                                'Value not in named-numbers.' in
                                packet.pkt_problems.get(path, {'Errors': [], 'Warnings': []})['Warnings']):

                            pkt_value[key] = unit_conversion(matches[0].value)

                        # If there are problems, do not add the packet
                        else:
                            break

                    # If the parameter was not found, do not add the packet
                    else:
                        break

                # If parameter has no defined path, set the value to None
                else:
                    pkt_value[key] = None

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
            lat, lon = first_packet.get('latitude', 0), first_packet.get('longitude', 0)

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

                if group_markers:
                    layers[packet_type] = (MarkerCluster(name=lgd_txt, overlay=True, control=True, show=False), color)
                else:
                    layers[packet_type] = (
                    folium.FeatureGroup(name=lgd_txt, overlay=True, control=True, show=False), color)

                layers[packet_type][0].add_to(self.map)
                self.map.add_child(layers[packet_type][0])

                stationIDs = []
                for packet in self.map_data:
                    if packet['stationID'] not in stationIDs and packet['type'] == packet_type:
                        stationIDs.append(packet['stationID'])

                for stationID in stationIDs:
                    stationID_layers[f'{packet_type}_{stationID}'] = folium.plugins.FeatureGroupSubGroup(
                        layers[packet_type][0], name=stationID, show=True)
                    stationID_layers[f'{packet_type}_{stationID}'].add_to(self.map)
                    self.map.add_child(stationID_layers[f'{packet_type}_{stationID}'])

            for packet in self.map_data:
                lat, lon = packet.get('latitude', 0), packet.get('longitude', 0)

                popup_text = (f'<b>Type:</b> {packet.get("type", "N/A")}<br>'
                              f'<b>Arrival time:</b> {packet.get("arrivalTime", "N/A")}<br>'
                              f'<b>Station ID:</b> {packet.get("stationID", "N/A")}<br>'
                              f'<b>Speed:</b> {packet.get("speed", "N/A")} km/h')

                folium.Marker([lat, lon], popup=popup_text, icon=folium.Icon(color=layers[packet['type']][1])).add_to(
                    stationID_layers[f'{packet['type']}_{packet['stationID']}'])

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
