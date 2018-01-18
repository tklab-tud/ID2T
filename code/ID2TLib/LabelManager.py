import os.path
from datetime import datetime
from xml.dom.minidom import *

import ID2TLib.Label as Label


class LabelManager:
    TAG_ROOT = 'LABELS'
    TAG_ATTACK = 'attack'
    TAG_ATTACK_NAME = 'attack_name'
    TAG_ATTACK_NOTE = 'attack_note'
    TAG_TIMESTAMP_START = 'timestamp_start'
    TAG_TIMESTAMP_END = 'timestamp_end'
    TAG_TIMESTAMP = 'timestamp'
    TAG_TIMESTAMP_HR = 'timestamp_hr'
    ATTR_VERSION = 'version_parser'

    # update this attribute if XML scheme was modified
    ATTR_VERSION_VALUE = '0.2'

    def __init__(self, filepath_pcap=None):
        """
        Creates a new LabelManager for managing the attack's labels.

        :param filepath_pcap: The path to the PCAP file associated to the labels.
        """
        self.labels = list()

        if filepath_pcap is not None:
            self.label_file_path = filepath_pcap.replace('.pcap', '_labels.xml')
            # only load labels if label file is existing
            if os.path.exists(self.label_file_path):
                self.load_labels()

    def add_labels(self, labels):
        """
        Adds a label to the internal list of labels.

        :param labels: The labels to be added
        """
        if isinstance(labels, list):
            self.labels = self.labels + [labels]
        elif isinstance(labels, tuple):
            for l in labels:
                self.labels.append(l)
        else:
            self.labels.append(labels)

        # sorts the labels ascending by their timestamp
        self.labels.sort()

    def write_label_file(self, filepath=None):
        """
        Writes previously added/loaded labels to a XML file. Uses the given filepath as destination path, if no path is
        given, uses the path in label_file_path.

        :param filepath: The path where the label file should be written to.
        """

        def get_subtree_timestamp(xml_tag_root, timestamp_entry):
            """
            Creates the subtree for a given timestamp, consisting of the unix time format (seconds) and a human-readable
            output.

            :param xml_tag_root: The tag name for the root of the subtree
            :param timestamp_entry: The timestamp as unix time
            :return: The root node of the XML subtree
            """
            timestamp_root = doc.createElement(xml_tag_root)

            # add timestamp in unix format
            timestamp = doc.createElement(self.TAG_TIMESTAMP)
            timestamp.appendChild(doc.createTextNode(str(timestamp_entry)))
            timestamp_root.appendChild(timestamp)

            # add timestamp in human-readable format
            timestamp_hr = doc.createElement(self.TAG_TIMESTAMP_HR)
            timestamp_hr_text = datetime.fromtimestamp(timestamp_entry).strftime('%Y-%m-%d %H:%M:%S.%f')
            timestamp_hr.appendChild(doc.createTextNode(timestamp_hr_text))
            timestamp_root.appendChild(timestamp_hr)

            return timestamp_root

        if filepath is not None:
            self.label_file_path = filepath.replace('.pcap', '_labels.xml')

        # Generate XML
        doc = Document()
        node = doc.createElement(self.TAG_ROOT)
        node.setAttribute(self.ATTR_VERSION, self.ATTR_VERSION_VALUE)
        for label in self.labels:
            xml_tree = doc.createElement(self.TAG_ATTACK)

            # add attack to XML tree
            attack_name = doc.createElement(self.TAG_ATTACK_NAME)
            attack_name.appendChild(doc.createTextNode(str(label.attack_name)))
            xml_tree.appendChild(attack_name)
            attack_note = doc.createElement(self.TAG_ATTACK_NOTE)
            attack_note.appendChild(doc.createTextNode(str(label.attack_note)))
            xml_tree.appendChild(attack_note)

            # add timestamp_start to XML tree
            xml_tree.appendChild(get_subtree_timestamp(self.TAG_TIMESTAMP_START, label.timestamp_start))

            # add timestamp_end to XML tree
            xml_tree.appendChild(get_subtree_timestamp(self.TAG_TIMESTAMP_END, label.timestamp_end))

            node.appendChild(xml_tree)

        doc.appendChild(node)

        # Write XML to file
        file = open(self.label_file_path, 'w')
        file.write(doc.toprettyxml())
        file.close()

    def load_labels(self):
        """
        Loads the labels from an already existing label XML file located at label_file_path (set by constructor).

        """

        def get_value_from_node(node, tag_name, *child_number):
            """
            Returns the value located in the tag specified by tag_name from a given node. Walks therefor the
            node's children along as indicated by child_number, e.g., childNumber = (1,2,) first goes to the 1st child, and
            then to the 2nd child of the first child -> elem.childNodes[1].childNodes[2].
            """
            elem = node.getElementsByTagName(tag_name)
            if len(elem) == 1:
                elem = elem[0]
                for c in child_number:
                    if len(elem.childNodes) > 0:
                        elem = elem.childNodes[c]
                    else:
                        return ""
                return elem.data
            else:
                return ""

        print("Label file found. Loading labels...")
        try:
            dom = parse(self.label_file_path)
        except Exception:
            print('ERROR: Provided label file could not be parsed. Ignoring label file')
            return

        # Check if version of parser and version of file match
        version = dom.getElementsByTagName(self.TAG_ROOT)
        if len(version) > 0:
            version = version[0].getAttribute(self.ATTR_VERSION)
            if version == [] or not version == self.ATTR_VERSION_VALUE:
                print(
                    "The file " + self.label_file_path + " was created by another version of ID2TLib.LabelManager. Ignoring label file.")

        # Parse attacks from XML file
        attacks = dom.getElementsByTagName(self.TAG_ATTACK)
        count_labels = 0
        for a in attacks:
            attack_name = get_value_from_node(a, self.TAG_ATTACK_NAME, 0)
            attack_note = get_value_from_node(a, self.TAG_ATTACK_NOTE, 0)
            timestamp_start = get_value_from_node(a, self.TAG_TIMESTAMP_START, 1, 0)
            timestamp_end = get_value_from_node(a, self.TAG_TIMESTAMP_END, 1, 0)
            label = Label.Label(attack_name, float(timestamp_start), float(timestamp_end), attack_note)
            self.labels.append(label)
            count_labels += 1

        print("Read " + str(count_labels) + " label(s) successfully.")
