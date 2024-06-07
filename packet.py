import re
import jsonpath_ng


class Packet(object):
    def __init__(self, msg_type, content, state='Not analysed', arrival_time=None, asn=None):
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
        self.type = msg_type
        self.state = state
        self.asn = asn

        self.data = process_packet(content) if isinstance(content, dict) else content

        # Initiate attribute of parameters
        self.parameters = []

        # Initiate attributes of output
        self.values = {}
        self.summary = {}
        self.problems = {}
        self.analysed = {}

    def analyse_packet(self, filter_mode, filter_parameters):
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

        def convert_item_path(input_path: list):
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
                        matches_element = jsonpath_ng.parse("$." + ".".join(asn_path)).find(self.asn)
                        path_converted[path_idx] = list(matches_element[0].value.keys())[0]
                    asn_path.append(path_converted[path_idx])
            else:
                asn_path = path_converted.copy()
            return path_converted, asn_path

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
            summary_key = '.'.join(current_parameter.path_converted)

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
            if current_parameter.problems:
                # Create problems key by joining path with dots
                problems_key = '.'.join(path)

                # Create a key in problems for this specific parameter
                self.problems[problems_key] = {'Warnings': None, 'Errors': None}

                self.problems[problems_key]['Warnings'] = [problem.desc for problem in current_parameter.problems if
                                                           problem.kind == 'Warning']
                self.problems[problems_key]['Errors'] = [problem.desc for problem in current_parameter.problems if
                                                         problem.kind == 'Error']

        class Parameter(object):
            class Problem(object):
                """
                A class to distinguish problems with parameters.
                The kind parameter can be either 'Warning' or 'Error'.
                """

                def __init__(self, kind, desc):
                    self.kind = kind
                    self.desc = desc

            def __init__(self, value, path, packet_asn, state='Not analysed'):
                def get_parameter_asn():
                    asn_matches = jsonpath_ng.parse("$." + ".".join(self.asn_path)).find(packet_asn)

                    if not asn_matches:
                        # Parameter not found in ASN dictionary
                        self.problems.append(
                            self.Problem('Error', 'ASN data type invalid or definition not found for this parameter.'))
                    else:
                        asn_definition = asn_matches[0].value

                        if asn_definition == 'ASN not found':
                            # This means that the ASN decompiler could not find a definition for this parameter type.
                            self.problems.append(
                                self.Problem('Error', 'ASN definition not found for this parameter.'))
                        elif not isinstance(asn_definition, dict):
                            # In case "asn" is not dict, throw a TypeError.
                            print(self.asn)
                            raise TypeError(f'ASN not dict type for parameter located on "{self.path}"')

                        return asn_definition

                self.name = '.'.join(path)
                self.value = value
                self.state = state
                self.path = path

                self.named_value = None
                self.problems = []
                self.asn_path, self.path_converted = convert_item_path(path)

                self.asn = get_parameter_asn()

            def analyse_parameter(self):
                # If there are none ASN related problems that were caught on init, analyse the parameter
                if not self.problems:
                    if 'type' in self.asn.keys():
                        """
                        'type' key is found in all data types except "SEQUENCE" and "CHOICE".
                        """

                        match self.asn['type']:

                            case 'INTEGER':
                                """
                                Checks restrictions (restricted values) and named numbers.
                                """
                                if not isinstance(self.value, int):
                                    self.problems.append(self.Problem('Error', f'Value is not of expected data type.'))
                                else:

                                    if 'restricted-to' in self.asn.keys():
                                        in_range = []
                                        for restriction in self.asn['restricted-to']:
                                            if restriction is not None:
                                                in_range.append(self.value in range(restriction[0], restriction[1] + 1))
                                        if not all(in_range):
                                            self.problems.append(self.Problem('Error', f'Value is out of range ({self.asn['restricted-to']}).'))
                                    if 'named-numbers' in self.asn.keys():

                                        # Try to determine if named-numbers try to provide only the unit of value, in which case
                                        # the program will not add a warning if value is not in named-numbers
                                        # This should cover most cases, but not all
                                        numbers = (
                                        'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
                                        'twenty', 'thirty', 'fourty', 'fifty', 'sixty', 'seventy', 'eighty', 'ninety',
                                        'hundred')
                                        named_num_is_unit = []
                                        for named_num in self.asn['named-numbers'].keys():
                                            named_num_is_unit.append(named_num.startswith(numbers))

                                        if self.value in self.asn['named-numbers'].values():
                                            self.named_value = list(self.asn['named-numbers'].keys())[
                                                list(self.asn['named-numbers'].values()).index(value)]

                                            if self.value == self.asn['named-numbers'].get('unavailable'):
                                                self.problems.append(self.Problem('Warning',
                                                                                  'Value is unavailable (named-numbers).'))
                                            elif self.value == self.asn['named-numbers'].get('outOfRange'):
                                                self.problems.append(self.Problem('Error',
                                                                                  'Value is out of range (named-numbers).'))

                                        elif not any(named_num_is_unit):
                                            self.problems.append(self.Problem('Warning', 'Value not in named-numbers.'))

                            case 'ENUMERATED':
                                """
                                Checks whether or not the value is in defined values or is 'unavailable' or 'outOfRange'.
                                """
                                if not isinstance(self.value, str):
                                    self.problems.append(self.Problem('Error', f'Value is not of expected data type.'))
                                else:

                                    if 'values' in self.asn.keys():
                                        value_list = []
                                        for i in self.asn['values']:
                                            if isinstance(i, tuple):
                                                value_list.append(i[0])
                                            else:
                                                value_list.append(i)
                                        if self.value not in value_list:
                                            self.problems.append(self.Problem('Error', 'Enumerate value not in defined values.'))
                                        elif self.value == 'unavailable':
                                            self.problems.append(self.Problem('Warning', 'Enumerate value set to unavailable.'))
                                        elif self.value == 'outOfRange':
                                            self.problems.append(self.Problem('Warning', 'Enumerate value set to out of range.'))

                            case 'IA5String' | 'NumericString':
                                """
                                Checks if value is in permitted sizes.
                                """
                                if not isinstance(self.value, str):
                                    self.problems.append(self.Problem('Error', f'Value is not of expected data type.'))
                                else:

                                    if 'size' in self.asn.keys():
                                        size_allowed = []
                                        for size in self.asn['size']:
                                            if not None:
                                                size_allowed.append(len(self.value) in range(size[0], size[1] + 1))
                                            else:
                                                size_allowed.append(self.value is None)
                                        if not all(size_allowed):
                                            self.problems.append(self.Problem('Error', f'Out of specified size ({self.asn['size']}).'))

                            case 'BIT STRING':
                                """
                                Checks if the number of bits is the same as size, pairs activated bits to their meanings.
                                """
                                if not isinstance(self.value, str):
                                    self.problems.append(self.Problem('Error', f'Value is not of expected data type.'))
                                else:

                                    if 'size' in self.asn.keys():
                                        if len(self.value) != self.asn['size'][0]:
                                            self.problems.append(self.Problem('Error', f'Out of specified size ({self.asn['size']}).'))
                                    if 'named-bits' in self.asn.keys():
                                        bits_activated = []
                                        for index, bit in enumerate(list(self.value)):
                                            if bit == '1':
                                                bits_activated.append(self.asn['named-bits'][index][0])
                                        self.named_value = bits_activated

                            case 'SEQUENCE OF':
                                """
                                Checks if number of values is in permitted size.
                                """
                                if not isinstance(self.value, list):
                                    self.problems.append(self.Problem('Error', f'Value is not of expected data type.'))
                                else:

                                    if 'size' in self.asn.keys():
                                        size_allowed = []
                                        for size in self.asn['size']:
                                            if not None:
                                                size_allowed.append(len(self.value.keys()) in range(size[0], size[1] + 1))
                                            else:
                                                size_allowed.append(self.value is None)
                                        if not all(size_allowed):
                                            self.problems.append(self.Problem('Error', f'Out of specified size ({self.asn['size']}).'))

                    elif 'member-type_type' in self.asn.keys():
                        """
                        "member-type_type" is found in only "SEQUENCE" and "CHOICE" parameter types.
                        The reason for the different naming of the key is that there might be a sub-parameter named "type", 
                        which would be then subsequently overwritten by the key 'type': 'SEQUENCE' or 'CHOICE'
                        """

                        match self.asn['member-type_type']:

                            case 'SEQUENCE':
                                """
                                Checks if all mandatory parameters are present (if not, error).
                                Checks if all optional parameters are present (if not, warning).
                                """
                                if not isinstance(self.value, dict):
                                    self.problems.append(self.Problem('Error', f'Value is not of expected data type.'))
                                else:

                                    for member, memAsnValue in self.asn.items():
                                        if isinstance(memAsnValue, dict) and member not in self.value.keys() and memAsnValue.get(
                                                'optional') is not True:
                                            self.problems.append(
                                                self.Problem('Error', f'Mandatory parameter {member} missing from Sequence.'))
                                        elif isinstance(memAsnValue,
                                                        dict) and member not in self.value.keys() and memAsnValue.get(
                                                'optional') is True:
                                            self.problems.append(
                                                self.Problem('Warning', f'Optional parameter {member} missing from Sequence.'))

                            case 'CHOICE':
                                """
                                Checks if only one of parameters specified in definition is present.
                                """
                                if not isinstance(self.value, dict):
                                    self.problems.append(self.Problem('Error', f'Value is not of expected data type.'))
                                else:

                                    if list(self.value.keys())[0] not in self.asn.keys():
                                        self.problems.append(
                                            self.Problem('Error', f'Mandatory parameter {list(self.value.keys())[0]} missing from '
                                                       f'Choice.'))

                # Evaluate the parameter to determine its final state
                self.evaluate_parameter()

            def evaluate_parameter(self):
                if not self.problems:
                    self.state = 'OK'
                elif all(problem.kind == 'Warning' for problem in self.problems):
                    self.state = 'Warning'
                else:
                    self.state = 'Error'

        if self.state == 'Not analysed':
            if isinstance(self.data[self.type], dict):

                # Main loop over all parameters (using recursive_parameters generator)
                for path, key, value in recursive_parameters(self.data):

                    # Create class object for this parameter
                    current_parameter = Parameter(value=value, path=path, packet_asn=self.asn)

                    # Establish filter condition
                    if filter_mode is None or not filter_parameters:
                        # If the filter mode is not specified or parameters to filter by are not specified,
                        # always proceed with the analysis of any parameter
                        filter_cond = True
                    else:
                        # Establish whitelist and blacklist conditions for analysing the parameter -- only if one of these
                        # is true, the parameter will be analysed, otherwise it will be skipped
                        wl_cond = filter_mode.lower() == 'whitelist' and '.'.join(current_parameter.asn_path) in filter_parameters
                        bl_cond = filter_mode.lower() == 'blacklist' and '.'.join(current_parameter.asn_path) not in filter_parameters
                        filter_cond = wl_cond or bl_cond

                    if filter_cond:
                        # Analyse the parameter
                        current_parameter.analyse_parameter()

                        # Add to summary and problems
                        add_to_statistics(current_parameter.state)

                        # Construct value to be assigned to parameter in analysed
                        analysed_value = (current_parameter.state, None if not current_parameter.problems else
                        [problem.desc for problem in current_parameter.problems])

                        # Add value to analysed
                        self.analysed[current_parameter.name] = analysed_value

                    # Update packet state accordingly
                    if current_parameter.state == 'Error':
                        self.state = 'Error'
                    elif current_parameter.state == 'Warning' and self.state != 'Error':
                        self.state = 'Warning'
                    elif current_parameter.state == 'OK' and self.state not in ['Error', 'Warning']:
                        self.state = 'OK'

                    # Add extended value into values
                    self.values[current_parameter.name] = [current_parameter.value, current_parameter.named_value]


            # There was a problem during decoding, in this case the data value type will be a string
            elif isinstance(self.data[self.type], str):
                # Set state to Error
                self.state = 'Error'

                # Split the string into several substrings, so that we can provide accurate output
                regex = r'^(.*?)\((.*?)\)'
                matches = re.search(regex, self.data[self.type])

                error_type = matches.group(1)
                error_message = matches.group(2).split(': ', 1)

                if len(error_message) == 2:
                    error_param = error_message[0]
                    error_desc = error_message[1]

                else:
                    error_param = self.type
                    error_desc = error_message[0]

                # Convert path for summary
                path_converted, asn_path = convert_item_path(error_param.split('.'))
                summary_key = '.'.join(path_converted)

                # Add to summary
                self.summary[summary_key] = [0, 0, 1]

                # Add to problems and analysed
                self.analysed[error_param] = ('Error', f'{error_type}: {error_desc}')
                self.problems[error_param] = {'Warnings': None,
                                                        'Errors': [f'{error_type}: {error_desc}']}

            else:
                raise TypeError(f'Value data type not dict or string.')
