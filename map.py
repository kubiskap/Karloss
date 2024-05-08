import folium
from folium.plugins import MarkerCluster
from folium.plugins import GroupedLayerControl
from statistics import mean
import branca
import random
import re


class Map(object):
    def __init__(self,
                 session_object,
                 packet_types,
                 default_icon='envelope',
                 merged_icon='list'):
        self.session_object = session_object
        self.packet_types = packet_types
        self.default_icon = default_icon
        self.merged_icon = merged_icon

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
        map_data = {}
        for packet in list(selected_packets):

            # Establish packet value
            pkt_value = {'type': (packet.type, None), 'arrivalTime': (packet.arrival_time, None)}

            # Get config for this packet
            pkt_config = self.session_object.config['mapConfig'][packet.type]['paths']

            innerBreak = False
            # For each parameter configured, find the value under this path
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

                # If parameter has no defined path, raise an Error
                else:
                    raise ValueError(f'Path of {key} parameter is not set in mapConfig.')

            # Get coordinates from the packet to use as a key in dictionary
            key = pkt_value.get('latitude', (0, None))[0], pkt_value.get('longitude', (0, None))[0]

            if not innerBreak:
                # Append the map packet data to the dictionary
                if key not in map_data:
                    map_data[key] = [pkt_value]
                else:
                    map_data[key].append(pkt_value)

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
            # Create a Folium map centered at average packet coordinates
            map_center = (mean([coord[0] for coord in self.map_data.keys()]),
                          mean([coord[1] for coord in self.map_data.keys()]))

            # Add OpenStreetMap tile layer
            layer_osm = folium.TileLayer(name='Open Street Map',
                                         max_native_zoom=19,
                                         max_zoom=30,
                                         tiles='https://tile.openstreetmap.org/{z}/{x}/{y}.png',
                                         attr='&copy; <a href="https://www.openstreetmap.org/copyright">'
                                              'OpenStreetMap</a> contributors')

            # Establish map object
            self.map = folium.Map(location=map_center, tiles=layer_osm, zoom_start = 12, max_zoom = 30)

            # Add OPNVKarte tile layer
            # Add OpenStreetMap tile layer
            layer_opnv = folium.TileLayer(name='Public Transport Map',
                                          max_native_zoom=18,
                                          max_zoom=30,
                                          tiles='https://tileserver.memomaps.de/tilegen/{z}/{x}/{y}.png',
                                          attr='Map <a href="https://memomaps.de/">memomaps.de</a>'
                                               '<a href="http://creativecommons.org/licenses/by-sa/2.0/">CC-BY-SA</a>, '
                                               'map data &copy; <a href="https://www.openstreetmap.org/copyright">'
                                               'OpenStreetMap</a> contributors')
            self.map.add_child(layer_opnv)

            # Add ESRI World Imagery tile layer
            layer_esri = folium.TileLayer(name='ESRI World Imagery',
                                          max_native_zoom=18,
                                          max_zoom=30,
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
                for entry in self.map_data.values():
                    for packet in entry:
                        if packet['stationID'][0] not in stationIDs and packet['type'][0] == packet_type:
                            stationIDs.append(packet['stationID'][0])

                for stationID in stationIDs:
                    stationID_layers[f'{packet_type}_{stationID}'] = folium.plugins.FeatureGroupSubGroup(
                        layers[packet_type][0], name=stationID, show=True)
                    stationID_layers[f'{packet_type}_{stationID}'].add_to(self.map)
                    self.map.add_child(stationID_layers[f'{packet_type}_{stationID}'])

            for coords, entry in self.map_data.items():

                merged_popup_text = [f'<b>{len(entry)} records at the same location.</b>']
                merged_parameters = {}

                for packet in entry:
                    # Get packet configuration
                    config = self.session_object.config['mapConfig'][packet.get("type")[0]]

                    # Create popup_text by joining all parameters of packet together in a fashionable way
                    popup_text = [f'<b>{re.sub(r"(\w)([A-Z])", r"\1 \2", key).title()}</b>: {value[0]}' for key, value
                                  in packet.items()]
                    popup_text = '<br>'.join(popup_text)

                    # Insert the popup text into an iframe to add a scrollbar to popup
                    iframe = branca.element.IFrame(
                        html=f'<div style="font: 12px/1.5 "Helvetica Neue", Arial, Helvetica, sans-serif;">'
                             f'{popup_text}</div>', width=250, height=250)

                    # Make tooltip text the formatted arrivalTime
                    tooltip_text = packet.get("arrivalTime")[0].strftime("%d.%m.%Y %H:%M:%S")

                    # Get parameter which will determine the icon from config, if none found, return default icon
                    try:
                        icon_parameter = list(config['icon'].keys())[0]

                        # Try to find icon for parameter
                        icon = config['icon'][icon_parameter][packet[icon_parameter][1]]

                    except KeyError:
                        # Set icon to default
                        icon = self.default_icon

                    if len(entry) == 1 or group_markers:
                        # If group_markers is true or there is only one entry at the location,
                        # we don't need to merge datapoints at the same location, meaning we can plot the marker now...

                        folium.Marker(coords, popup=folium.Popup(iframe, max_width=250), tooltip=tooltip_text,
                                      icon=folium.Icon(color=layers[packet['type'][0]][1], icon=icon, prefix='fa')
                                      ).add_to(stationID_layers[f'{packet['type'][0]}_{packet['stationID'][0]}'])
                    else:
                        merged_popup_text.append(popup_text)

                        for parameter, value in packet.items():
                            if parameter in merged_parameters:
                                merged_parameters[parameter].append(value)
                            else:
                                merged_parameters[parameter] = [value]

                # If group_markers is false and there are more entries at the location,
                # proceed in adding merged datapoint into the map.
                if len(entry) > 1 and not group_markers:

                    # If the packets to be grouped are of the same stationID and packet type, proceed with grouping
                    if len(set(merged_parameters.get('stationID'))) == 1 and len(set(merged_parameters.get('type'))) == 1:

                        config = self.session_object.config['mapConfig'][merged_parameters.get("type")[0][0]]

                        # Sort the arrivalTimes list to get the timeframe of marker
                        arrivalTimes = sorted([value[0] for value in merged_parameters.get('arrivalTime')])

                        if arrivalTimes[0].date() == arrivalTimes[-1].date():
                            tooltip_text = (f'{arrivalTimes[0].strftime("%d.%m.%Y %H:%M:%S")}-'
                                            f'{arrivalTimes[-1].strftime("%H:%M:%S")}')
                        else:
                            tooltip_text = (f'{arrivalTimes[0].strftime("%d.%m.%Y %H:%M:%S")}-'
                                            f'{arrivalTimes[-1].strftime("%d.%m.%Y %H:%M:%S")}')

                        # Divide the popup text with horizontal lines
                        merged_popup_text = '<hr>'.join(merged_popup_text)

                        # Insert the merged text into an iframe to add a scrollbar to popup
                        iframe = branca.element.IFrame(
                            html=f'<div style="font: 12px/1.5 Helvetica Neue;">'
                                 f'{merged_popup_text}</div>', width=250, height=250)

                        # If an icon parameter in merged_packets has the same value, set the icon to the one configured
                        icon_parameter = list(config['icon'].keys())[0]
                        if len(set(merged_parameters.get(icon_parameter))) == 1:
                            try:
                                # Try to find icon for parameter
                                icon = config['icon'][icon_parameter][merged_parameters.get(icon_parameter)[0][1]]
                            except KeyError:
                                # Set icon to default
                                icon = self.default_icon
                        else:
                            # Else set icon to predefined "Merged" icon
                            icon = self.merged_icon

                        # Add Marker to map with the 'Merged' icon
                        folium.Marker(coords, popup=folium.Popup(iframe, max_width=250), tooltip=tooltip_text,
                                      icon=folium.Icon(color=layers[merged_parameters.get('type')[0][0]][1], icon=icon, prefix='fa')
                                      ).add_to(stationID_layers[f'{merged_parameters.get('type')[0][0]}_'
                                                                f'{merged_parameters.get('stationID')[0][0]}'])

                    # If not, plot them individually
                    else:
                        for packet in entry:
                            # Get packet configuration
                            config = self.session_object.config['mapConfig'][packet.get("type")[0]]

                            # Create popup_text by joining all parameters of packet together in a fashionable way
                            popup_text = [f'<b>{re.sub(r"(\w)([A-Z])", r"\1 \2", key).title()}</b>: {value[0]}' for
                                          key, value
                                          in packet.items()]
                            popup_text = '<br>'.join(popup_text)

                            # Insert the popup text into an iframe to add a scrollbar to popup
                            iframe = branca.element.IFrame(
                                html=f'<div style="font: 12px/1.5 "Helvetica Neue", Arial, Helvetica, sans-serif;">'
                                     f'{popup_text}</div>', width=250, height=250)

                            # Make tooltip text the formatted arrivalTime
                            tooltip_text = packet.get("arrivalTime")[0].strftime("%d.%m.%Y %H:%M:%S")

                            # Get parameter which will determine the icon from config, if none found, return default icon
                            try:
                                icon_parameter = list(config['icon'].keys())[0]

                                # Try to find icon for parameter
                                icon = config['icon'][icon_parameter][packet[icon_parameter][1]]

                            except KeyError:
                                # Set icon to default
                                icon = self.default_icon

                            folium.Marker(coords, popup=folium.Popup(iframe, max_width=250), tooltip=tooltip_text,
                                          icon=folium.Icon(color=layers[packet['type'][0]][1], icon=icon, prefix='fa')
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
