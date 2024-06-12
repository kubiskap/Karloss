import argparse
import tkinter as tk

from Karloss.gui import ConfigurationWindow
from Karloss.core import Instance


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

    def display_message(message, is_error=False):
        """Display prompt or error message."""
        prefix = "[Error] " if is_error else "[Prompt] "
        print(f"{prefix}{message}", end='')

    def get_input_with_prompt(prompt_message):
        """Get input from the user with a prompt message."""
        display_message(prompt_message)
        return input()

    def get_expected_value():
        """Prompt user to enter the expected value parameter path."""
        while True:
            parameter = get_input_with_prompt('Enter the full path to the parameter: ')
            if isinstance(parameter, str) and len(parameter.split('.')) > 1:
                return parameter
            display_message('Invalid input.', is_error=True)

    def get_expected_value_value():
        """Prompt user to enter the expected value or multiple values for a parameter."""
        while True:
            value = get_input_with_prompt('Enter the expected value of the parameter or enter "multiple" if you wish to specify multiple expected values: ')
            if value == 'multiple':
                values = []
                i = 1
                while True:
                    multiple_value = get_input_with_prompt(f'Enter expected value of the parameter. [no. {i}, type "done" to finish entry]: ')
                    if multiple_value.lower() == 'done':
                        break
                    elif multiple_value:
                        values.append(multiple_value)
                        i += 1
                    else:
                        display_message('Invalid input.', is_error=True)
                return values
            elif value:
                return value
            display_message('Invalid input.', is_error=True)

    def prompt_for_expected_value():
        """Prompt user to define an expected value of a parameter."""
        while True:
            define_expected_value = get_input_with_prompt('Do you wish to define an expected value of a parameter? [y/N]: ') or 'n'
            if define_expected_value.lower() == 'y':
                parameter = get_expected_value()
                value = get_expected_value_value()
                return {parameter: value}
            elif define_expected_value.lower() == 'n':
                return {}
            display_message('Invalid input.', is_error=True)

    def get_filter_mode(entity):
        """Prompt user to select filter mode (whitelist/blacklist) for packets or parameters."""
        while True:
            mode = get_input_with_prompt(f'Which mode do you want to use to filter the {entity}? [whitelist/blacklist]: ')
            if mode.lower() in ['blacklist', 'whitelist']:
                return mode.lower()
            display_message('Invalid input.', is_error=True)

    def get_filter_list(entity, mode):
        """Prompt user to enter filter list for packets or parameters."""
        filter_list = []
        i = 1
        while True:
            item = get_input_with_prompt(f'Enter {entity} to be included in the {mode} filter. [no. {i}, type "done" to finish entry]: ')
            if item.lower() == 'done':
                break
            elif isinstance(item, str):
                filter_list.append(item.upper())
                i += 1
            else:
                display_message('Invalid input.', is_error=True)
        return filter_list

    def prompt_for_packet_filter():
        """Prompt user to filter packets to be analysed based on their type."""
        while True:
            filter_packets = get_input_with_prompt('Do you wish to filter packets to be analysed based on their type? [y/N]: ') or 'n'
            if filter_packets.lower() == 'y':
                mode = get_filter_mode('packets')
                filter_list = get_filter_list('packet type', mode)
                return mode, filter_list
            elif filter_packets.lower() == 'n':
                return 'Undefined', []
            display_message('Invalid input.', is_error=True)

    def prompt_for_parameter_filter():
        """Prompt user to filter parameters to be analysed based on their path."""
        while True:
            filter_parameters = get_input_with_prompt('Do you wish to filter parameters to be analysed based on their path? [y/N]: ') or 'n'
            if filter_parameters.lower() == 'y':
                mode = get_filter_mode('parameters')
                filter_list = get_filter_list('parameter path', mode)
                return mode, filter_list
            elif filter_parameters.lower() == 'n':
                return 'Undefined', []
            display_message('Invalid input.', is_error=True)

    # Launch a new instance of Karloss
    karloss_instance = Instance(config_location=config_file)

    # Import the file specified
    karloss_instance.import_file(input_file=pcap_file)

    # Prompt for expected value
    parameter_expected_val = prompt_for_expected_value()

    # Prompt for packet filtering
    packet_filter_mode, filter_packets = prompt_for_packet_filter()

    # Prompt for parameter filtering
    parameter_filter_mode, filter_parameters = prompt_for_parameter_filter()



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
