import importlib
import datetime as dt
import os.path
import xml.dom.minidom as minidom
import pytz as pytz

import ID2TLib.Label as Label
import ID2TLib.TestLibrary as Lib


class LabelManager:
    TAG_ROOT = 'labels'
    TAG_INPUT = 'input'
    TAG_OUTPUT = 'output'
    TAG_FILE_NAME = 'filename'
    TAG_FILE_HASH = 'sha256'
    TAG_ATTACK = 'attack'
    TAG_ATTACK_NAME = 'name'
    TAG_ATTACK_NOTE = 'note'
    TAG_ATTACK_SEED = 'seed'
    TAG_ATTACK_PACKETS = 'injected_packets'
    TAG_TIMESTAMP_START = 'timestamp_start'
    TAG_TIMESTAMP_END = 'timestamp_end'
    TAG_TIMESTAMP = 'timestamp'
    TAG_TIMESTAMP_HR = 'timestamp_hr'
    TAG_PARAMETERS = 'parameters'
    ATTR_VERSION = 'version_parser'
    ATTR_PARAM_USERSPECIFIED = 'user_specified'

    # update this attribute if XML scheme was modified
    ATTR_VERSION_VALUE = '0.3'

    def __init__(self, filepath_pcap=None):
        """
        Creates a new LabelManager for managing the attack's labels.

        :param filepath_pcap: The path to the PCAP file associated to the labels.
        """
        self.labels = list()
        self.filepath_input_pcap = filepath_pcap

        if filepath_pcap is not None:
            self.label_file_path = os.path.splitext(filepath_pcap)[0] + '_labels.xml'
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

        def get_subtree_fileinfo(xml_tag_root, filename) -> minidom.Element:
            """
            Creates the subtree for pcap file information (filename and hash).

            :return: The root node of the XML subtree
            """

            input_root = doc.createElement(xml_tag_root)

            file = doc.createElement(self.TAG_FILE_NAME)
            file.appendChild(doc.createTextNode(os.path.split(filename)[-1]))
            input_root.appendChild(file)

            hash_node = doc.createElement(self.TAG_FILE_HASH)
            hash_node.appendChild(doc.createTextNode(Lib.get_sha256(filename)))
            input_root.appendChild(hash_node)

            return input_root

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
            timestamp_hr_text = dt.datetime.fromtimestamp(timestamp_entry).astimezone(pytz.timezone('UTC')).strftime('%Y-%m-%d %H:%M:%S.%f')
            timestamp_hr.appendChild(doc.createTextNode(timestamp_hr_text))
            timestamp_root.appendChild(timestamp_hr)

            return timestamp_root

        def get_subtree_parameters(parameters):
            """
            Creates a subtree containing all parameters used to construct the attack

            :param parameters: The list of parameters used to run the attack
            :return: The root node of the XML subtree
            """
            parameters_root = doc.createElement(self.TAG_PARAMETERS)

            for param_key, param_value in parameters.items():
                param = doc.createElement(param_key.value)
                param.appendChild(doc.createTextNode(str(param_value.value)))
                param.setAttribute(self.ATTR_PARAM_USERSPECIFIED, str(param_value.user_specified))
                parameters_root.appendChild(param)

            return parameters_root

        if filepath is not None:
            self.label_file_path = os.path.splitext(filepath)[0] + '_labels.xml'

        # Generate XML
        doc = minidom.Document()
        node = doc.createElement(self.TAG_ROOT)
        node.setAttribute(self.ATTR_VERSION, self.ATTR_VERSION_VALUE)
        node.appendChild(get_subtree_fileinfo(self.TAG_INPUT, self.filepath_input_pcap))
        node.appendChild(get_subtree_fileinfo(self.TAG_OUTPUT, filepath))

        for label in self.labels:
            xml_tree = doc.createElement(self.TAG_ATTACK)

            # add attack to XML tree
            attack_name = doc.createElement(self.TAG_ATTACK_NAME)
            attack_name.appendChild(doc.createTextNode(str(label.attack_name)))
            xml_tree.appendChild(attack_name)
            attack_note = doc.createElement(self.TAG_ATTACK_NOTE)
            attack_note.appendChild(doc.createTextNode(str(label.attack_note)))
            xml_tree.appendChild(attack_note)
            attack_seed = doc.createElement(self.TAG_ATTACK_SEED)
            attack_seed.appendChild(doc.createTextNode(str(label.seed)))
            xml_tree.appendChild(attack_seed)
            injected_packets = doc.createElement(self.TAG_ATTACK_PACKETS)
            injected_packets.appendChild(doc.createTextNode(str(label.injected_packets)))
            xml_tree.appendChild(injected_packets)

            # add timestamp_start to XML tree
            xml_tree.appendChild(get_subtree_timestamp(self.TAG_TIMESTAMP_START, label.timestamp_start))

            # add timestamp_end to XML tree
            xml_tree.appendChild(get_subtree_timestamp(self.TAG_TIMESTAMP_END, label.timestamp_end))

            # add parameters to XML tree
            xml_tree.appendChild(get_subtree_parameters(label.parameters))

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
            node's children along as indicated by child_number, e.g., childNumber = (1,2,) first goes to the 1st child,
            and then to the 2nd child of the first child -> elem.childNodes[1].childNodes[2].
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
            dom = minidom.parse(self.label_file_path)
        except Exception:
            # TODO: more specific exception
            print('ERROR: Provided label file could not be parsed. Ignoring label file')
            return

        # Check if version of parser and version of file match
        version = dom.getElementsByTagName(self.TAG_ROOT)
        if len(version) > 0:
            version = version[0].getAttribute(self.ATTR_VERSION)
            if version == [] or not version == self.ATTR_VERSION_VALUE:
                print(
                    "The file " + self.label_file_path + " was created by another version of ID2TLib.LabelManager. "
                                                         "Ignoring label file.")

        self.input_filename = get_value_from_node(dom, self.TAG_INPUT, 1, 0)
        self.input_hash = get_value_from_node(dom, self.TAG_INPUT, 3, 0)
        self.output_filename = get_value_from_node(dom, self.TAG_OUTPUT, 1, 0)
        self.output_hash = get_value_from_node(dom, self.TAG_OUTPUT, 3, 0)

        # Parse attacks from XML file
        attacks = dom.getElementsByTagName(self.TAG_ATTACK)
        count_labels = 0
        for a in attacks:
            attack_name = get_value_from_node(a, self.TAG_ATTACK_NAME, 0)
            attack_note = get_value_from_node(a, self.TAG_ATTACK_NOTE, 0)
            timestamp_start = get_value_from_node(a, self.TAG_TIMESTAMP_START, 1, 0)
            timestamp_end = get_value_from_node(a, self.TAG_TIMESTAMP_END, 1, 0)
            attack_seed = get_value_from_node(a, self.TAG_ATTACK_SEED, 0)

            # Instantiate this attack to create a parameter list with the correct types
            attack_module = importlib.import_module("Attack." + attack_name)
            attack_class = getattr(attack_module, attack_name)
            attack = attack_class()

            # Loop through all parameters listed in the XML file
            param = a.getElementsByTagName(self.TAG_PARAMETERS)[0]
            for param in param.childNodes:
                # Skip empty text nodes returned by minidom
                if not isinstance(param, minidom.Text):
                    import distutils.util
                    param_name = param.tagName
                    param_value = param.childNodes[0].nodeValue
                    param_userspecified = bool(distutils.util.strtobool(param.getAttribute(self.ATTR_PARAM_USERSPECIFIED)))
                    attack.add_param_value(param_name, param_value, param_userspecified)

            # Create the label from the data read
            label = Label.Label(attack_name, float(timestamp_start), float(timestamp_end), attack_seed, attack.params,
                                attack_note)
            self.labels.append(label)
            count_labels += 1

        print("Read " + str(count_labels) + " label(s) successfully.")
