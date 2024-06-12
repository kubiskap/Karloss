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
    For smooth user experience, run the CLI sequence which will be used by most users.
    """

    # Launch a new instance of Karloss
    karloss_instance = Instance(config_location=config_file)

    # Import the file specified
    karloss_instance.import_file(input_file=pcap_file)

    # -- Ask for analysis parameters
    # Expected value parameter prompt
    while True:
        prompt_define_expected_value = input('[Prompt] Do you wish to define an expected value of a parameter? [y/N]: ') or 'n'

        if prompt_define_expected_value.lower() == 'y':

            while True:
                prompt_expected_parameter = input('[Prompt] Enter the full path to the parameter: ')

                if isinstance(prompt_expected_parameter, str):
                    if len(prompt_expected_parameter.split('.')) > 1:
                        break
                    else:
                        print('[Error] Invalid input. ', end='')
                else:
                    print('[Error] Invalid input. ', end='')

            while True:

                prompt_expected_parameter_value = input('[Prompt] Enter the expected value of the parameter or enter "multiple",'
                                                        ' if you wish to specify multiple expected values: ')

                if prompt_expected_parameter_value == 'multiple':
                    prompt_expected_parameter_value, i = [], 1
                    while True:
                        prompt_define_expected_value_multiple = input(f'[Prompt] Enter expected value of the parameter. '
                                                    f'[no. {i}, type "done" to finish entry]: ')

                        if prompt_define_expected_value_multiple.lower() == 'done':
                            break
                        elif prompt_define_expected_value_multiple:
                            prompt_expected_parameter_value.append(prompt_define_expected_value_multiple)
                            i += 1
                        else:
                            print('[Error] Invalid input. ', end='')
                elif prompt_expected_parameter_value:
                    break
                else:
                    print('[Error] Invalid input. ', end='')

            parameter_expected_val = {prompt_expected_parameter: prompt_expected_parameter_value}
            break

        elif prompt_define_expected_value.lower() == 'n':
            parameter_expected_val = {}
            break
        else:
            print('[Error] Invalid input. ', end='')

    # Packet filtering prompt
    while True:
        prompt_filter_packets = input(
            '[Prompt] Do you wish to filter packets to be analysed based on their type? [y/N]: ') or 'n'

        if prompt_filter_packets.lower() == 'y':

            while True:
                prompt_filter_packets_mode = input('[Prompt] Which mode do you want to use to filter the packets? '
                                                   '[whitelist/blacklist]: ')

                if prompt_filter_packets_mode.lower() in ['blacklist', 'whitelist']:
                    packet_filter_mode = prompt_filter_packets_mode.lower()
                    break
                else:
                    print('[Error] Invalid input. ', end='')

            # Init filter_packets list
            filter_packets, i = [], 1

            while True:
                prompt_filter_packets_types = input(f'[Prompt]  packet type to be included in the packet '
                                                    f'{packet_filter_mode} filter. '
                                                    f'[no. {i}, type "done" to finish entry]: ')

                if prompt_filter_packets_types.lower() == 'done':
                    break
                elif isinstance(prompt_filter_packets_types, str):
                    filter_packets.append(prompt_filter_packets_types.upper())
                    i += 1
                else:
                    print('[Error] Invalid input. ', end='')

            break

        elif prompt_filter_packets.lower() == 'n':
            packet_filter_mode, filter_packets = 'Undefined', []
            break

        else:
            print('[Error] Invalid input. ', end='')

    # Parameter filtering prompt
    while True:
        prompt_filter_parameters = input(
            '[Prompt] Do you wish to filter parameters to be analysed based on their path? [y/N]: ') or 'n'

        if prompt_filter_parameters.lower() == 'y':

            while True:
                prompt_filter_parameters_mode = input('[Prompt] Which mode do you want to use to filter the parameters? '
                                                      '[whitelist/blacklist]: ')

                if prompt_filter_parameters_mode.lower() in ['blacklist', 'whitelist']:
                    parameter_filter_mode = prompt_filter_parameters_mode.lower()
                    break
                else:
                    print('[Error] Invalid input. ', end='')

            # Init filter_packets list
            filter_parameters = [], 1

            while True:
                prompt_filter_parameters_types = input(f'[Prompt] Enter parameter path to be included in the packet '
                                                       f'{packet_filter_mode} filter. '
                                                       f'[no. {i}, type "done" to finish entry]: ')

                if prompt_filter_parameters_types.lower() == 'done':
                    break
                elif isinstance(prompt_filter_parameters_types, str):
                    filter_packets.append(prompt_filter_parameters_types.upper())
                    i += 1
                else:
                    print('[Error] Invalid input. ', end='')

            break

        elif prompt_filter_parameters.lower() == 'n':
            parameter_filter_mode, filter_parameters = 'Undefined', []
            break

        else:
            print('[Error] Invalid input. ', end='')

    # Analyse the file imported based on the options chosen
    karloss_instance.analyse(parameter_expected_value=parameter_expected_val,
                             packet_filter_mode=packet_filter_mode, filter_packets=filter_packets,
                             parameter_filter_mode=parameter_filter_mode, filter_parameters=filter_parameters)


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
