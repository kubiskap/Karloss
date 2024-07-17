import asn1tools
from collections import ChainMap
import sys


class ItsMessage(object):
    """
    A generic ITS message class.
    Main purpose is to decode encoded data using asn1tools package and to rebuild the decoded asn dictionary to similar
    structure of the final decoded message nested dictionary.
    """

    def __init__(
            self,
            asn_files,
            msg_name,
    ):
        self.its_dictionary = asn1tools.parse_files(asn_files)
        self.msg_name = msg_name
        self.asn_rebuilt = self.rebuild_asn()

    def decode(self, encoded, encoding_type='uper'):
        """
        Method used to decode extracted encoded data from pyshark using asn1tools and ASN.1 specification. Returns
        """

        # Compile the dictionary
        try:
            compiled_dict = asn1tools.compile_dict(self.its_dictionary, encoding_type)
        except asn1tools.CompileError as CompError:
            print(f'{repr(CompError).split('(')[0]}({str(CompError)})')
            sys.exit()

        try:
            content = compiled_dict.decode(self.msg_name, encoded, check_constraints=False)

        except asn1tools.DecodeError or asn1tools.ConstraintsError as ASNerror:
            content = f'{repr(ASNerror).split('(')[0]}({str(ASNerror)})'

        except Exception as OtherError:
            content = f'{repr(OtherError).split('(')[0]}({str(OtherError)})'

        return content

    def rebuild_asn(self):
        types = dict(ChainMap(*[self.its_dictionary[container]['types'] for container in self.its_dictionary]))
        object_classes = dict(
            ChainMap(*[self.its_dictionary[container]['object-classes'] for container in self.its_dictionary]))

        def asn_algorithm(parameter_name: str, parameter_path=None) -> dict:
            if parameter_path is None:
                parameter_path = []

            def process_members(input_dict: dict, path: list) -> dict:
                members_dict = {}
                for value in input_dict.get('members'):
                    if value is not None:
                        if value['type'] in types:
                            members_dict[value['name']] = process_type(value, path + [value['name']]) | {key: value for
                                                                                                         key, value in
                                                                                                         value.items()
                                                                                                         if
                                                                                                         key not in [
                                                                                                             'type',
                                                                                                             'name']}
                        elif value['type'].split('.')[0] in object_classes:
                            members_dict[value['name']] = process_object_class(value, path + [value['name']])
                        elif value['type'] in ['SEQUENCE', 'CHOICE']:
                            members_dict[value['name']] = process_members(value, path + [value['name']]) | {key: value
                                                                                                            for
                                                                                                            key, value
                                                                                                            in
                                                                                                            value.items()
                                                                                                            if
                                                                                                            key not in [
                                                                                                                'type',
                                                                                                                'name']}
                        elif value['type'] == 'SEQUENCE OF':
                            members_dict[value['name']] = process_sequence_of(value, path) | {key: value for key, value
                                                                                              in
                                                                                              value.items() if
                                                                                              key not in ['type',
                                                                                                          'element',
                                                                                                          'name']}
                        else:
                            members_dict[value['name']] = value
                    else:
                        break
                return members_dict | {'member-type_type': input_dict['type']}

            def process_object_class(value: dict, path: list) -> str:
                object_class_type = value['type'].split('.')
                for object_class_member in object_classes.get(object_class_type[0])['members']:
                    if object_class_member['name'] == object_class_type[1]:
                        return list(asn_algorithm(object_class_member['type'], path).values())[0]

            def process_type(value: dict, path: list) -> dict:
                return list(asn_algorithm(value['type'], path).values())[0]

            def process_sequence_of(value: dict, path: list) -> dict:
                output = value.copy()
                try:
                    element_asn = asn_algorithm(value['element']['type'], path + ['element', value['element']['type']])
                except KeyError:
                    element_asn = asn_algorithm(list(value['element'])[0], path + ['element', list(value['element'])[0]])
                output['element'] = element_asn
                return output

            def has_repeating_pairs(path):
                path_no_element = [i for i in path if i != 'element']
                count_pairs = {}
                for i in range(len(path_no_element) - 1):
                    pair = (path_no_element[i], path_no_element[i + 1])
                    if pair in count_pairs:
                        return True
                    count_pairs[pair] = 1
                return False

            def find_reference_element_path(path):
                reference_element_name = path.pop(-1)

                for idx, element in enumerate(path):
                    if element == reference_element_name:
                        return path[:idx + 1]

            parameter_asn = types.get(parameter_name)
            key_name = parameter_path[-1] if parameter_path else parameter_name
            output_dict = {}

            # Loop prevention
            if has_repeating_pairs(parameter_path):
                output_dict[key_name] = {'loopDetected': True,
                                         'referenceParameterPath': find_reference_element_path(parameter_path)}

            elif parameter_asn is not None:
                if parameter_asn['type'] in types:
                    output_dict[key_name] = process_type(parameter_asn, parameter_path)
                elif parameter_asn['type'].split('.')[0] in object_classes:
                    output_dict[key_name] = process_object_class(parameter_asn, parameter_path)
                elif parameter_asn['type'] in ['SEQUENCE', 'CHOICE']:
                    output_dict[key_name] = process_members(parameter_asn, parameter_path)
                elif parameter_asn['type'] == 'SEQUENCE OF':
                    output_dict[key_name] = process_sequence_of(parameter_asn, parameter_path)
                else:
                    output_dict[key_name] = parameter_asn
            else:
                output_dict[key_name] = 'ASN not found'
            return output_dict

        return asn_algorithm(self.msg_name, [self.msg_name])


