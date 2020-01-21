import re
import typing as t

import Attack.ParameterTypes.BaseType as BaseType


class Port(BaseType.ParameterType):

    def __init__(self):
        super(Port, self).__init__()
        self.name = "Port"

    def validate(self, value: int) -> (bool, int):
        return Port._is_port(value)

    @staticmethod
    def _is_port(ports_input: t.Union[t.List[str], t.List[int], str, int])\
            -> t.Union[bool, t.Tuple[bool, t.List[t.Union[int, str]]]]:
        """
        Verifies if the given value is a valid port. Accepts port ranges, like 80-90, 80..99, 80...99.

        :param ports_input: The port number as int or string.
        :return: True if the port number is valid, otherwise False. If a single port or a comma-separated list of ports
        was given, a list of int is returned. If a port range was given, the range is resolved
        and a list of int is returned.
        """

        def _is_invalid_port(num: int) -> bool:
            """
            Checks whether the port number is invalid.

            :param num: The port number as int.
            :return: True if the port number is invalid, otherwise False.
            """
            return num < 1 or num > 65535

        if ports_input == None or ports_input == "":
            return False

        if isinstance(ports_input, str):
            ports_input = ports_input.replace(' ', '').split(',')
        elif isinstance(ports_input, int):
            ports_input = [ports_input]
        elif len(ports_input) == 0:
            return False

        ports_output = []

        for port_entry in ports_input:
            if isinstance(port_entry, int):
                if _is_invalid_port(port_entry):
                    return False
                ports_output.append(port_entry)
            # TODO: validate last condition
            elif isinstance(port_entry, str) and port_entry.isdigit():
                # port_entry describes a single port
                port_entry = int(port_entry)
                if _is_invalid_port(port_entry):
                    return False
                ports_output.append(port_entry)
            elif '-' in port_entry or '..' in port_entry:
                # port_entry describes a port range
                # allowed format: '1-49151', '1..49151', '1...49151'
                match = re.match(r'^([0-9]{1,5})(?:-|\.{2,3})([0-9]{1,5})$', str(port_entry))
                # check validity of port range
                # and create list of ports derived from given start and end port
                (port_start, port_end) = int(match.group(1)), int(match.group(2))
                if _is_invalid_port(port_start) or _is_invalid_port(port_end):
                    return False
                else:
                    ports_list = [i for i in range(port_start, port_end + 1)]
                # append ports at ports_output list
                ports_output += ports_list

        if isinstance(ports_output, list) and len(ports_output) == 1:
            return True, ports_output[0]
        else:
            return True, ports_output
