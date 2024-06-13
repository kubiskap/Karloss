import argparse
import tkinter as tk
import os

from Karloss.gui import ConfigurationWindow
from Karloss.core import Instance
from Karloss.map import Map


def launch_gui():
    """
    Launch the GUI window.
    """
    config_root = tk.Tk()
    config_app = ConfigurationWindow(config_root)
    config_root.mainloop()


def launch_cli_sequence(config_file, pcap_file):
    """
    For a smooth user experience, run the CLI sequence which will be used by most users.
    """

    def display_message(message, type='info'):
        """Display prompt or error message."""

        prefix = type.title()
        print(f"[{prefix}] {message}")

    def get_input_with_prompt(prompt_message):
        """Get input from the user with a prompt message."""
        return input(f'[Prompt] {prompt_message}')

    def get_expected_value_parameter(idx):
        """Prompt user to enter the expected value parameter path."""
        while True:
            parameter_path = get_input_with_prompt(f'Enter the full path to the parameter. [no. {idx}, type "done" to '
                                                   f'finish entry]: ')
            if isinstance(parameter_path, str) and len(parameter_path.split('.')) > 1:
                return parameter_path
            elif parameter_path == 'done':
                return parameter_path
            display_message('Invalid input: the path needs to be separated with dots (".").', type='error')

    def get_expected_value_value():
        """Prompt user to enter the expected value or multiple values for a parameter."""
        while True:
            value = get_input_with_prompt('Enter the expected value of the parameter '
                                          'or enter "multiple" if you wish to specify multiple expected values: ')
            if value == 'multiple':
                values = []
                i = 1
                while True:
                    multiple_value = get_input_with_prompt(f'Enter expected value of the parameter. '
                                                           f'[no. {i}, type "done" to finish entry]: ')
                    if multiple_value.lower() == 'done':
                        break
                    elif multiple_value:
                        values.append(multiple_value)
                        i += 1
                    else:
                        display_message('Invalid input: enter the expected value or "done" '
                                        'to finish multiple value entry.', type='error')
                return values
            elif value:
                return value
            display_message('Invalid input: enter the expected value or "multiple" '
                            'to start multiple value entry.', type='error')

    def prompt_for_expected_value():
        """Prompt user to define an expected value of a parameter."""
        while True:
            define_expected_value = get_input_with_prompt('Do you wish to define an expected value of a parameter? [y/N]: ') or 'n'
            if define_expected_value.lower()[0] == 'y':
                expected_parameters, i = {}, 1
                while True:
                    parameter_path = get_expected_value_parameter(i)

                    if parameter_path != 'done':
                        value = get_expected_value_value()
                        expected_parameters[parameter_path] = value
                        i += 1
                    else:
                        break

                return expected_parameters
            elif define_expected_value.lower()[0] == 'n':
                return {}
            display_message('Invalid input: enter "y" or "n".', type='error')

    def get_filter_mode(entity):
        """Prompt user to select filter mode (whitelist/blacklist) for packets or parameters."""
        while True:
            mode = get_input_with_prompt(f'Which mode do you want to use to filter the {entity}? [whitelist/blacklist]: ')
            if mode.lower() in ['blacklist', 'whitelist']:
                return mode.lower()
            display_message('Invalid input: enter "blacklist" or "whitelist".', type='error')

    def get_filter_list(entity, mode):
        """Prompt user to enter filter list for packets or parameters."""
        filter_list = []
        i = 1
        while True:
            item = get_input_with_prompt(f'Enter {entity} to be included in the {mode} filter. [no. {i}, type "done" to finish entry]: ')
            if item.lower() == 'done':
                break
            elif isinstance(item, str) and item:
                filter_list.append(item)
                i += 1
            else:
                display_message(f'Invalid input: enter a string with {entity} name or "done" '
                                f'to finish entry.',type='error')
        return filter_list

    def prompt_for_packet_filter():
        """Prompt user to filter packets to be analysed based on their type."""
        while True:
            filter_packets = get_input_with_prompt('Do you wish to filter packets to be analysed based on '
                                                   'their type? [y/N]: ') or 'n'
            if filter_packets.lower()[0] == 'y':
                mode = get_filter_mode('packets')
                filter_list = [packet_type.upper() for packet_type in get_filter_list('packet type', mode)]
                return mode, filter_list
            elif filter_packets.lower()[0] == 'n':
                return 'Undefined', []
            display_message('Invalid input: enter "y" or "n".', type='error')

    def prompt_for_parameter_filter():
        """Prompt user to filter parameters to be analysed based on their path."""
        while True:
            filter_parameters = get_input_with_prompt('Do you wish to filter parameters to be analysed based on their path? [y/N]: ') or 'n'
            if filter_parameters.lower()[0] == 'y':
                mode = get_filter_mode('parameters')
                filter_list = get_filter_list('parameter path', mode)
                return mode, filter_list
            elif filter_parameters.lower()[0] == 'n':
                return 'Undefined', []
            display_message('Invalid input: enter "y" or "n".', type='error')

    def prompt_for_output_location():
        """Prompt user to choose the output location."""
        while True:
            output_location = get_input_with_prompt('Enter the output location: ')

            if os.path.exists(output_location):
                return os.path.abspath(output_location)
            elif isinstance(output_location, str):
                display_message('Invalid input: the path you entered does not exist.', type='error')
            else:
                display_message('Invalid input: the path you entered is in invalid format. Please enter a valid path '
                                'in form of string.', type='error')

    def prompt_for_map_plot_decision():
        """Prompt user to choose whether he wants to plot map or not"""
        while True:
            plot_map_prompt = get_input_with_prompt('Do you wish to plot a map for a visual representations of '
                                                    'the results of analysis? [y/N]: ') or 'n'
            if plot_map_prompt.lower()[0] == 'y':
                return True
            elif plot_map_prompt.lower()[0] == 'n':
                return False
            display_message('Invalid input: enter "y" or "n".', type='error')

    def prompt_for_group_markers():
        while True:
            group_markers_prompt = get_input_with_prompt('Do you wish to group markers on the map? [Y/n]: ') or 'y'
            if group_markers_prompt.lower()[0] == 'y':
                return True
            elif group_markers_prompt.lower()[0] == 'n':
                return False
            display_message('Invalid input: enter "y" or "n".', type='error')

    # Launch a new instance of Karloss
    karloss_instance = Instance(config_location=config_file)

    # Import the file specified
    karloss_instance.import_file(input_file=pcap_file)

    """
    Analyse
    """
    # Prompt for expected value
    parameter_expected_val = prompt_for_expected_value()

    # Prompt for packet filtering
    packet_filter_mode, filter_packets = prompt_for_packet_filter()

    # Prompt for parameter filtering
    parameter_filter_mode, filter_parameters = prompt_for_parameter_filter()

    # Analyse the pcap with given parameters
    karloss_instance.analyse(parameter_expected_value=parameter_expected_val,
                             packet_filter_mode=packet_filter_mode, filter_packets=filter_packets,
                             parameter_filter_mode=parameter_filter_mode, filter_parameters=filter_parameters)
    """
    Output results
    """
    # Prompt user
    output_path = prompt_for_output_location()

    # Output the results
    karloss_instance.output_results(output_location=output_path)

    """
    Map plotting
    """
    # Prompt user whether he wants to plot map
    plot_map = prompt_for_map_plot_decision()

    if plot_map:

        while True:
            # Prompt for packet types
            map_packet_types = [packet_type.upper() for packet_type in
                                get_filter_list('map packet types', 'whitelist')]

            # Prompt for output_location
            map_output_location = prompt_for_output_location()

            # Prompt for group_markers
            map_group_markers = prompt_for_group_markers()

            try:
                karloss_instance.plot_map(packet_types=map_packet_types, output_location=map_output_location,
                                          group_markers=map_group_markers)
                break
            except ReferenceError:
                display_message('Invalid input: you have entered packet types not present in the mapConfig.',
                                type='error')


def main():
    parser = argparse.ArgumentParser(description="Karloss Packet Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Subparser for GUI
    gui_parser = subparsers.add_parser("gui", help="Run the GUI")

    # Subparser for command-line analysis
    cli_parser = subparsers.add_parser("cli", help="Run default CLI sequence")
    cli_parser.add_argument("config", help="Path to the config.json file")
    cli_parser.add_argument("pcap", help="Path to the pcap file")

    args = parser.parse_args()

    if args.command == "gui":
        launch_gui()
    elif args.command == "cli":
        launch_cli_sequence(args.config, args.pcap)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
