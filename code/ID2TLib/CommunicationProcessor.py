from lea import Lea
from random import randrange
from Attack.MembersMgmtCommAttack import MessageType
from Attack.MembersMgmtCommAttack import Message

# needed because of machine inprecision. E.g A time difference of 0.1s is stored as >0.1s
EPS_TOLERANCE = 1e-13  # works for a difference of 0.1, no less

def greater_than(a: float, b: float):
    """
    A greater than operator desgined to handle slight machine inprecision up to EPS_TOLERANCE.
    :return: True if a > b, otherwise False
    """
    return b - a < -EPS_TOLERANCE

class CommunicationProcessor():
    """
    Class to process parsed input CSV/XML data and retrieve a mapping or other information.
    """

    def __init__(self, mtypes:dict, nat:bool):
        """
        Creates an instance of CommunicationProcessor.
        :param packets: the list of abstract packets
        :param mtypes: a dict containing an int to EnumType mapping of MessageTypes
        :param nat: whether NAT is present in this network
        """
        self.packets = []
        self.mtypes = mtypes
        self.nat = nat

    def set_mapping(self, packets: list, mapped_ids: dict):
        """
        Set the selected mapping for this communication processor.

        :param packets: all packets contained in the mapped time frame
        :param mapped_ids: the chosen IDs
        """
        self.packets = packets
        self.local_init_ids = set(mapped_ids)

    def get_comm_interval(self, cpp_comm_proc, strategy: str, number_ids: int, max_int_time: int, start_idx: int, end_idx: int):
        """
        Finds a communication interval with respect to the given strategy. The interval is maximum of the given seconds 
        and has at least number_ids communicating initiators in it.
        
        :param cpp_comm_proc: An instance of the C++ communication processor that stores all the input messages and 
                              is responsible for retrieving the interval(s)
        :param strategy: The selection strategy (i.e. random, optimal, custom)
        :param number_ids: The number of initiator IDs that have to exist in the interval(s)
        :param max_int_time: The maximum time period of the interval
        :param start_idx: The message index the interval should start at (None if not specified)
        :param end_idx: The message index the interval should stop at (inclusive) (None if not specified)
        :return: A dict representing the communication interval. It contains the initiator IDs, 
                 the start index and end index of the respective interval. The respective keys 
                 are {IDs, Start, End}. If no interval is found, an empty dict is returned.
        """

        if strategy == "random":
            # try finding not-empty interval 5 times
            for i in range(5):
                start_idx = randrange(0, cpp_comm_proc.get_message_count())
                interval = cpp_comm_proc.find_interval_from_startidx(start_idx, number_ids, max_int_time)
                if interval and interval["IDs"]:
                    return interval
            return {}
        elif strategy == "optimal":
            intervals = cpp_comm_proc.find_optimal_interval(number_ids, max_int_time)
            if not intervals:
                return {}
            else:
                for i in range(5):
                    interval = intervals[randrange(0, len(intervals))]
                    if interval and interval["IDs"]:
                        return interval

                return {}
        elif strategy == "custom":
            if (not start_idx) and (not end_idx):
                print("Custom strategy was selected, but no (valid) start or end index was specified.")
                print("Because of this, a random interval is selected.")
                start_idx = randrange(0, cpp_comm_proc.get_message_count())
                interval = cpp_comm_proc.find_interval_from_startidx(start_idx, number_ids, max_int_time)
            elif (not start_idx) and end_idx:
                end_idx -= 1  # because message indices start with 1 (for the user)
                interval = cpp_comm_proc.find_interval_from_endidx(end_idx, number_ids, max_int_time)
            elif start_idx and (not end_idx):
                start_idx -= 1  # because message indices start with 1 (for the user)
                interval = cpp_comm_proc.find_interval_from_startidx(start_idx, number_ids, max_int_time)
            elif start_idx and end_idx:
                start_idx -= 1; end_idx -= 1
                ids = cpp_comm_proc.get_interval_init_ids(start_idx, end_idx)
                if not ids:
                    return {}
                return {"IDs": ids, "Start": start_idx, "End": end_idx}

            if not interval or not interval["IDs"]:
                return {}
            return interval

    def det_id_roles_and_msgs(self):
        """
        Determine the role of every mapped ID. The role can be initiator, responder or both.
        On the side also connect corresponding messages together to quickly find out
        which reply belongs to which request and vice versa.

        :return: the selected messages
        """

        mtypes = self.mtypes
        # setup initial variables and their values
        respnd_ids = set()
        # msgs --> the filtered messages, msg_id --> an increasing ID to give every message an artificial primary key
        msgs, msg_id = [], 0
        # keep track of previous request to find connections
        prev_reqs = {}
        # used to determine whether a request has been seen yet, so that replies before the first request are skipped and do not throw an error by
        # accessing the empty dict prev_reqs (this is not a perfect solution, but it works most of the time)
        req_seen = False
        local_init_ids = self.local_init_ids
        external_init_ids = set()

        # process every packet individually 
        for packet in self.packets:
            id_src, id_dst, msg_type, time = packet["Src"], packet["Dst"], int(packet["Type"]), float(packet["Time"])
            lineno = packet.get("LineNumber", -1)
            # if if either one of the IDs is not mapped, continue
            if (id_src not in local_init_ids) and (id_dst not in local_init_ids):
                continue

            # convert message type number to enum type
            msg_type = mtypes[msg_type]

            # process a request
            if msg_type in {MessageType.SALITY_HELLO, MessageType.SALITY_NL_REQUEST}:
                if not self.nat and id_dst in local_init_ids and id_src not in local_init_ids:
                    external_init_ids.add(id_src)
                elif id_src not in local_init_ids:
                    continue
                else:
                    # process ID's role
                    respnd_ids.add(id_dst)
                # convert the abstract message into a message object to handle it better
                msg_str = "{0}-{1}".format(id_src, id_dst)
                msg = Message(msg_id, id_src, id_dst, msg_type, time, line_no = lineno)
                msgs.append(msg)
                prev_reqs[msg_str] = msg_id
                msg_id += 1
                req_seen = True

            # process a reply
            elif msg_type in {MessageType.SALITY_HELLO_REPLY, MessageType.SALITY_NL_REPLY} and req_seen:
                if not self.nat and id_src in local_init_ids and id_dst not in local_init_ids:
                    # process ID's role
                    external_init_ids.add(id_dst)
                elif id_dst not in local_init_ids:
                    continue
                else: 
                    # process ID's role
                    respnd_ids.add(id_src)
                # convert the abstract message into a message object to handle it better
                msg_str = "{0}-{1}".format(id_dst, id_src)
                # find the request message ID for this response and set its reference index
                refer_idx = prev_reqs[msg_str]
                msgs[refer_idx].refer_msg_id = msg_id
                msg = Message(msg_id, id_src, id_dst, msg_type, time, refer_idx, lineno)
                msgs.append(msg)
                # remove the request to this response from storage
                del(prev_reqs[msg_str])
                msg_id += 1

            elif msg_type == MessageType.TIMEOUT and id_src in local_init_ids and not self.nat:
                # convert the abstract message into a message object to handle it better
                msg_str = "{0}-{1}".format(id_dst, id_src)
                # find the request message ID for this response and set its reference index
                refer_idx = prev_reqs.get(msg_str)
                if refer_idx is not None:
                    msgs[refer_idx].refer_msg_id = msg_id
                    if msgs[refer_idx].type == MessageType.SALITY_NL_REQUEST:
                        msg = Message(msg_id, id_src, id_dst, MessageType.SALITY_NL_REPLY, time, refer_idx, lineno)
                    else:
                        msg = Message(msg_id, id_src, id_dst, MessageType.SALITY_HELLO_REPLY, time, refer_idx, lineno)
                    msgs.append(msg)
                    # remove the request to this response from storage
                    del(prev_reqs[msg_str])
                    msg_id += 1

        # store the retrieved information in this object for later use
        self.respnd_ids = sorted(respnd_ids)
        self.external_init_ids = sorted(external_init_ids)
        self.messages = msgs

        # return the selected messages
        return self.messages

    def det_ext_and_local_ids(self, prob_rspnd_local: int=0):
        """
        Map the given IDs to a locality (i.e. local or external} considering the given probabilities.

        :param comm_type: the type of communication (i.e. local, external or mixed)
        :param prob_rspnd_local: the probabilty that a responder is local
        """
        external_ids = set()
        local_ids = self.local_init_ids.copy()
        
        # set up probabilistic chooser
        rspnd_locality = Lea.fromValFreqsDict({"local": prob_rspnd_local*100, "external": (1-prob_rspnd_local)*100})

        for id_ in self.external_init_ids:
            external_ids.add(id_)

        # determine responder localities
        for id_ in self.respnd_ids:
            if id_ in local_ids or id_ in external_ids:
                continue 
            
            pos = rspnd_locality.random() 
            if pos == "local":
                local_ids.add(id_)
            elif pos == "external":
                external_ids.add(id_)

        self.local_ids, self.external_ids = local_ids, external_ids
        return self.local_ids, self.external_ids