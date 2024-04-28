import jsonpath_ng
import copy

from msg import ItsMessage


class Packet(object):
    def __init__(self, msg_type, content, arrival_time):
        def process_packet(input_dict):
            """
            Internal method to convert the raw decoded packet into a true dictionary.
            """

            def process_list(input_list):
                output_dict = {}
                for index, item in enumerate(input_list):
                    match item:
                        case list():
                            output_dict[f'listItem{index}'] = process_list(item)
                        case dict():
                            output_dict[f'listItem{index}'] = process_packet(item)
                        case _:
                            output_dict[f'listItem{index}'] = item
                return output_dict

            output_dict = {}  # Establishes output

            for key, value in input_dict.items():

                # Convert CHOICE, which returns (str, value) into {str: value}
                if isinstance(value, tuple) and isinstance(value[0], str):
                    output_dict[key] = process_packet({value[0]: value[1]})

                # Convert BIT STRING, which returns (bytes, int) to bits
                elif isinstance(value, tuple) and isinstance(value[0], bytes) and isinstance(value[1], int):
                    binary_string = ''.join(format(byte, '08b') for byte in value[0])
                    binary = binary_string[:value[1]]
                    output_dict[key] = binary

                # Convert nested lists into dictionary
                elif isinstance(value, list):
                    output_dict[key] = process_list(value)

                # If value is dict, go one level deeper
                elif isinstance(value, dict):
                    output_dict[key] = process_packet(value)

                elif isinstance(value, bytes):
                    output_dict[key] = str(value)

                else:
                    output_dict[key] = value
            return output_dict

        self.arrival_time = arrival_time

        self.data = process_packet(content) if isinstance(content, dict) else content
        self.type = msg_type
        self.state = 'Not analysed'

        # Initiate attributes used for packet analysis results
        self.analysed = {}
        self.values = {}
        self.summary = {}
        self.problems = {}

    def analyse_packet(self, asn_dictionary: dict):
        def recursive_parameters(packet: dict, path=None):
            """
            Generator used to iterate through every parameter of the packet in "analyse_packet" function.
            """
            if path is None:
                path = []

            for key, value in packet.items():
                if isinstance(value, dict):
                    yield from recursive_parameters(value, path + [key])
                elif isinstance(value, list):
                    for index, item in enumerate(value):
                        yield from recursive_parameters(item, path + [key] + [index])
                yield path + [key], key, value

        def convert_item_path(input_path: list) -> tuple[list, str]:
            """
            Sub-function that converts path containing any "listItem" keys. Determines type of item based on superior
            parameter and replaces each "listItem" with the parameter in specification of superior parameter (which should
            always be of type "SEQUENCE OF".

            Also converts path of the asn specification, which corresponds to asn_dictionary structure.
            """

            path_converted = input_path.copy()
            if any('listItem' in path_keys for path_keys in path_converted):
                asn_path = []
                for path_idx, path_item in enumerate(path_converted):
                    if path_item.startswith('listItem') and not path_converted[path_idx - 1].startswith('listItem'):
                        asn_path.append('element')
                        matches_element = jsonpath_ng.parse("$." + ".".join(asn_path)).find(asn_dictionary)
                        path_converted[path_idx] = list(matches_element[0].value.keys())[0]
                    asn_path.append(path_converted[path_idx])
            else:
                asn_path = path_converted.copy()
            return path_converted, asn_path

        class Problem(object):
            """
            A class to distinguish problems with parameters.
            The flag parameter can be either 0 (problem which is then added to summary as 'Warning') and 1 ('Error').
            """

            def __init__(self, flag, desc):
                self.flag = flag
                self.desc = desc

        def analyse_parameter():

            if 'type' in asn.keys():
                """
                'type' key is found in all data types except "SEQUENCE" and "CHOICE".
                """

                match asn['type']:

                    case 'INTEGER':
                        """
                        Checks restrictions (restricted values) and named numbers.
                        """

                        if 'restricted-to' in asn.keys():
                            in_range = []
                            for restriction in asn['restricted-to']:
                                if restriction is not None:
                                    in_range.append(value in range(restriction[0], restriction[1] + 1))
                            if not all(in_range):
                                problems.append(Problem(1, f'Value is out of range ({asn['restricted-to']}).'))
                        if 'named-numbers' in asn.keys():

                            # Try to determine if named-numbers try to provide only the unit of value, in which case
                            # the program will not add a warning if value is not in named-numbers
                            # This should cover most cases, but not all
                            numbers = ('one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
                                       'twenty', 'thirty', 'fourty', 'fifty', 'sixty', 'seventy', 'eighty', 'ninety',
                                       'hundred')
                            named_num_is_unit = []
                            for named_num in asn['named-numbers'].keys():
                                named_num_is_unit.append(named_num.startswith(numbers))

                            if value in asn['named-numbers'].values():
                                extended_value[1] = list(asn['named-numbers'].keys())[
                                                      list(asn['named-numbers'].values()).index(value)]

                                if value == asn['named-numbers'].get('unavailable'):
                                    problems.append(Problem(0, 'Value is unavailable (named-numbers).'))
                                elif value == asn['named-numbers'].get('outOfRange'):
                                    problems.append(Problem(1, 'Value is out of range (named-numbers).'))

                            elif not any(named_num_is_unit):
                                problems.append(Problem(0, 'Value not in named-numbers.'))

                    case 'ENUMERATED':
                        """
                        Checks whether or not the value is in defined values or is 'unavailable' or 'outOfRange'.
                        """
                        if 'values' in asn.keys():
                            value_list = []
                            for i in asn['values']:
                                if isinstance(i, tuple):
                                    value_list.append(i[0])
                                else:
                                    value_list.append(i)
                            if value not in value_list:
                                problems.append(Problem(1, 'Enumerate value not in defined values.'))
                            elif value == 'unavailable':
                                problems.append(Problem(0, 'Enumerate value set to unavailable.'))
                            elif value == 'outOfRange':
                                problems.append(Problem(0, 'Enumerate value set to out of range.'))

                    case 'IA5String' | 'NumericString' | 'SEQUENCE OF':
                        """
                        Checks if value is in permitted sizes.
                        """
                        if 'size' in asn.keys():
                            size_allowed = []
                            for size in asn['size']:
                                if not None:
                                    size_allowed.append(len(value) in range(size[0], size[1] + 1))
                                else:
                                    size_allowed.append(value is None)
                            if not all(size_allowed):
                                problems.append(Problem(1, f'Out of specified size ({asn['size']}).'))

                    case 'BIT STRING':
                        """
                        Checks if the number of bits is the same as size, pairs activated bits to their meanings.
                        """
                        if 'size' in asn.keys():
                            if len(value) != asn['size'][0]:
                                problems.append(Problem(1, f'Out of specified size ({asn['size']}).'))
                        if 'named-bits' in asn.keys():
                            bits_activated = []
                            for index, bit in enumerate(list(value)):
                                if bit == '1':
                                    bits_activated.append(asn['named-bits'][index][0])
                            extended_value[1] = bits_activated

                    case 'SEQUENCE OF':
                        """
                        Checks if number of values is in permitted size.
                        """
                        if 'size' in asn.keys():
                            size_allowed = []
                            for size in asn['size']:
                                if not None:
                                    size_allowed.append(len(value.keys()) in range(size[0], size[1] + 1))
                                else:
                                    size_allowed.append(value is None)
                            if not all(size_allowed):
                                problems.append(Problem(1, f'Out of specified size ({asn['size']}).'))

            elif 'member-type_type' in asn.keys():
                """
                "member-type_type" is found in only "SEQUENCE" and "CHOICE" parameter types.
                The reason for the different naming of the key is that there might be a sub-parameter named "type", 
                which would be then subsequently overwritten by the key 'type': 'SEQUENCE' or 'CHOICE'
                """

                match asn['member-type_type']:

                    case 'SEQUENCE':
                        """
                        Checks if all mandatory parameters are present (if not, error).
                        Checks if all optional parameters are present (if not, warning).
                        """
                        for member, memAsnValue in asn.items():
                            if isinstance(memAsnValue, dict) and member not in value.keys() and memAsnValue.get(
                                    'optional') is not True:
                                problems.append(Problem(1, f'Mandatory parameter {member} missing from Sequence.'))
                            elif isinstance(memAsnValue, dict) and member not in value.keys() and memAsnValue.get(
                                    'optional') is True:
                                problems.append(Problem(0, f'Optional parameter {member} missing from Sequence.'))

                    case 'CHOICE':
                        """
                        Checks if only one of parameters specified in definition is present.
                        """
                        if list(value.keys())[0] not in asn.keys():
                            problems.append(Problem(1, f'Mandatory parameter {list(value.keys())[0]} missing from '
                                                       f'Choice.'))

        def add_to_statistics(summary_state: str):
            """
            Function to fill in the packet summary and packet errors.

            In summary, we don't want to distinguish between individual parameters, so we use path_converted as key.
            Not distinguishing between individual  parameters rather than parameter types makes it easier to spot
            a pattern with the errors/warnings.
            Each value of a summary key is a list of 3 integers, that represent a number of parameters within the packet
            that have a state:
            -- 1st: OK,
            -- 2nd: Warning,
            -- 3rd: Error.

            In pkt_errors, we want to list the individual parameters and their errors/warning, so we use path as key.
            Each value of a pkt_errors key is a nested list. The first list is filled individual warning descriptions,
            the second list is filled with individual error descriptions.
            """

            # # SUMMARY # #
            # Create summary key by joining path_converted with dots
            summary_key = '.'.join(path_converted)

            # If there is already key created, just add the value into the array
            if summary_key in self.summary:
                match summary_state:
                    case 'Error':
                        self.summary[summary_key][2] += 1
                    case 'Warning':
                        self.summary[summary_key][1] += 1
                    case 'OK':
                        self.summary[summary_key][0] += 1

            # If the key has not yet been created, create it and add value into the array
            else:
                # Create the key
                self.summary[summary_key] = [0, 0, 0]  # OK, Warning, Error
                # Add the value to the key
                add_to_statistics(summary_state)

            # # PKT_PROBLEMS # #
            if problems:
                # Create problems key by joining path with dots
                problems_key = '.'.join(path)

                # Create a key in problems for this specific parameter
                self.problems[problems_key] = {'Warnings': None, 'Errors': None}

                self.problems[problems_key]['Warnings'] = [problem.desc for problem in problems if
                                                           problem.flag == 0]
                self.problems[problems_key]['Errors'] = [problem.desc for problem in problems if problem.flag == 1]

        def evaluate_parameter():
            # If the parameter is evaluated as an Error, set both the parameter and packet state as Error
            if 1 in problem_flags:
                self.state = 'Error'
                return 'Error'

            # If the parameter is evaluated as Warning, set parameter state to Warning and packet state to
            # Warning only if it has not been yet set to Error
            elif 0 in problem_flags:
                self.state = 'Warning' if self.state != 'Error' else self.state
                return 'Warning'

            # If there has not been Error or Warning detected, set parameter state to OK and packet state
            # to OK, only if it has not been set to Warning or Error
            else:
                self.state = 'OK' if self.state not in ['Error', 'Warning'] else self.state
                return 'OK'

        if self.state == 'Not analysed':
            if isinstance(self.data, dict):

                # Main loop over all parameters (using recursive_parameters generator)
                for path, key, value in recursive_parameters(self.data):

                    # Convert the path if there are any listItems
                    path_converted, asn_path = convert_item_path(path)

                    # Establish the array of problems for the parameter, adding class objects of Problem to the list
                    problems = []

                    # Find the asn definition of the parameter in asn_dictionary and deal with ASN related errors
                    asn_matches = jsonpath_ng.parse("$." + ".".join(asn_path)).find(asn_dictionary)
                    if not asn_matches:
                        # Parameter not found in ASN dictionary
                        problems.append(
                            Problem(1, 'ASN data type invalid or definition not found for this parameter.'))
                    else:
                        asn = asn_matches[0].value

                        if asn == 'ASN not found':
                            # This means that the ASN decompiler could not find a definition for this parameter type.
                            problems.append(
                                Problem(1, 'ASN definition not found for this parameter.'))
                        elif not isinstance(asn, dict):
                            # In case "asn" is not dict, throw a TypeError.
                            print(asn)
                            raise TypeError(f'ASN not dict type for parameter located on "{path}"')

                    # Establish extended value (second element being named-number value or bits_activated)
                    extended_value = [value, None]

                    # If there are no problems with the ASN, analyse the parameter
                    if not problems:
                        # Analyse the parameter
                        analyse_parameter()

                    """
                    Evaluate the parameter state after analysis
                    """
                    # Stack problems into lists
                    problem_flags, problem_descs = ([problem.flag for problem in problems],
                                                    [problem.desc for problem in problems])

                    # Evaluate parameter
                    parameter_state = evaluate_parameter()

                    # Add to summary and problems
                    add_to_statistics(parameter_state)

                    # Join path to create flattened dict key
                    flatdict_key = '.'.join(path)

                    # Add extended value into values
                    self.values[flatdict_key] = extended_value

                    # Construct value to be assigned to parameter in analysed
                    analysed_value = (parameter_state, None if not problem_flags else problem_descs)

                    # Add value to analysed
                    self.analysed['.'.join(path)] = analysed_value

            # There was a problem during decoding, in this case the data value type will be a string
            elif isinstance(self.data, str):
                # Set state to error
                self.state = 'Error'

                # Split the string into several substrings, so that we can provide accurate output
                splitstring = self.data.split('(')
                error_type = splitstring[0]

                split_splitstring = splitstring[1].split(': ')
                faulty_parameter_path = split_splitstring[0]
                problem_description = split_splitstring[1]

                # Convert path for summary
                path_converted, asn_path = convert_item_path(faulty_parameter_path.split('.'))
                summary_key = '.'.join(path_converted)

                # Add to summary
                if summary_key in self.summary:
                    self.summary[summary_key][2] += 1
                else:
                    self.summary[summary_key] = [0, 0, 1]

                # Add to problems and analysed
                self.analysed[faulty_parameter_path] = ('Error', problem_description)
                self.problems[faulty_parameter_path] = {'Warnings': None,
                                                        'Errors': [f'{error_type}: {problem_description}']}

            else:
                raise TypeError(f'Value data type not dict or string.')

        else:
            print('Packet has already been analysed.')
