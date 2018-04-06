import os.path
from xml.dom.minidom import *
import datetime


class MessageMapping:
    TAG_MAPPING_GROUP = "mappings"
    TAG_MAPPING = "mapping"

    ATTR_ID = "id"
    ATTR_LINENO = "line_number"
    ATTR_HAS_PACKET = "mapped"

    ATTR_PACKET_TIME = "packet_time"

    def __init__(self, messages, pcap_start_timestamp_str):
        self.messages = messages
        self.id_to_packet = {}
        ts_date_format = "%Y-%m-%d %H:%M:%S.%f"
        first_msg_dt = datetime.datetime.fromtimestamp(min(messages, key=lambda msg: msg.time).time)
        orig_pcap_start_dt = datetime.datetime.strptime(pcap_start_timestamp_str, ts_date_format)
        self.pcap_start_dt = min(first_msg_dt, orig_pcap_start_dt)

    def map_message(self, message, packet):
        self.id_to_packet[message.msg_id] = packet

    def to_xml(self, ):
        doc = Document()

        mappings = doc.createElement(self.TAG_MAPPING_GROUP)
        doc.appendChild(mappings)

        for message in sorted(self.messages, key=lambda msg: msg.time):
            mapping = doc.createElement(self.TAG_MAPPING)
            mapping.setAttribute(self.ATTR_ID, str(message.msg_id))
            mapping.setAttribute(self.ATTR_LINENO, str(message.line_no))

            mapping.setAttribute("Src", str(message.src["ID"]))
            mapping.setAttribute("Dst", str(message.dst["ID"]))
            mapping.setAttribute("Type", str(message.type.value))
            mapping.setAttribute("CSV_XML_Time", str(message.csv_time))

            dt = datetime.datetime.fromtimestamp(message.time)
            dt_relative = dt - self.pcap_start_dt
            mapping.setAttribute("PCAP_Time-Timestamp", str(message.time))
            mapping.setAttribute("PCAP_Time-Datetime", dt.strftime("%Y-%m-%d %H:%M:%S.") + str(dt.microsecond))
            mapping.setAttribute("PCAP_Time-Relative", "%d.%s" % (dt_relative.total_seconds(), str(dt_relative.microseconds).rjust(6, "0")))

            packet = self.id_to_packet.get(message.msg_id)
            mapping.setAttribute(self.ATTR_HAS_PACKET, "true" if packet is not None else "false")
            if packet:
                mapping.setAttribute(self.ATTR_PACKET_TIME, str(packet.time))

            mappings.appendChild(mapping)

        return doc

    def write_to(self, buffer, close = True):
        buffer.write(self.to_xml().toprettyxml())
        if close: buffer.close()

    def write_to_file(self, filename: str, *args, **kwargs):
        self.write_to(open(filename, "w", *args, **kwargs))

    def write_next_to_pcap_file(self, pcap_filename : str, mapping_ext = "_mapping.xml", *args, **kwargs):
        pcap_base = os.path.splitext(pcap_filename)[0]

        self.write_to_file(pcap_base + mapping_ext, *args, **kwargs)
