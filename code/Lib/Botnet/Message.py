from enum import Enum


class MessageType(Enum):
    """
    Defines possible botnet message types
    """

    TIMEOUT = 3
    SALITY_NL_REQUEST = 101
    SALITY_NL_REPLY = 102
    SALITY_HELLO = 103
    SALITY_HELLO_REPLY = 104

    def is_request(self):
        """
        Checks whether the given message type is a request or not.
        :return: True if it is a request, False otherwise
        """
        return self in [MessageType.SALITY_HELLO, MessageType.SALITY_NL_REQUEST]

    def is_response(self):
        """
        Checks whether the given message type is a response or not.
        :return: True if it is a response, False otherwise
        """
        return self in [MessageType.SALITY_HELLO_REPLY, MessageType.SALITY_NL_REPLY]


class Message:
    INVALID_LINENO = -1

    """
    Defines a compact message type that contains all necessary information.
    """

    def __init__(self, msg_id: int, src, dst, type_: MessageType, time: float, refer_msg_id: int = -1, line_no=-1):
        """
        Constructs a message with the given parameters.

        :param msg_id: the ID of the message
        :param src: something identifying the source, e.g. ID or configuration
        :param dst: something identifying the destination, e.g. ID or configuration
        :param type_: the type of the message
        :param time: the timestamp of the message
        :param refer_msg_id: the ID this message is a request for or reply to. -1 if there is no related message.
        :param line_no: The line number this message appeared at in the original CSV file
        """
        self.msg_id = msg_id
        self.src = src
        self.dst = dst
        self.type = type_
        self.time = time
        self.csv_time = time
        self.refer_msg_id = refer_msg_id
        self.line_no = line_no

    def __str__(self):
        str_ = "{0}. at {1}: {2}-->{3}, {4}, refer:{5} (line {6})".format(self.msg_id, self.time, self.src, self.dst,
                                                                          self.type, self.refer_msg_id, self.line_no)
        return str_
