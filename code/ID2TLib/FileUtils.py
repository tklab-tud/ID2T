import xml.etree.ElementTree as ElementTree
import csv
import os

def parse_xml(filepath: str):
	'''
	Parses an XML File
	It is assumed, that packets are placed on the second hierarchical level and packetinformation is encoded as attributes

	:param filepath: the path to the XML file to be parsed
	:return: a List of Dictionaries, each Dictionary contains the information of one packet
	'''

	tree = ElementTree.parse(filepath)
	root = tree.getroot()

	#Convert Tree to List of Dictionaries
	packets = []
	for child in root:
		packets.append(child.attrib)

	return packets

def parse_csv_to_xml(filepath: str):
	'''
	Converts a CSV file into an XML file. Every entry is converted to a child with respective attributes of the root node

	:param filepath: the path to the CSV file to be parsed
	:return: a path to the newly created XML file
	'''

	filename = os.path.splitext(filepath)[0]
	# build a tree structure
	root = ElementTree.Element("trace")
	root.attrib["path"] = filename

	# parse the csvFile into reader
	with open(filepath, "rt") as csvFile:
		reader = csv.reader(csvFile, delimiter=",")
		# loop through the parsed file, creating packet-elements with the structure of the csvFile as attributes
		lineno = -1 # lines start at zero
		for line in reader:
			lineno += 1
			if not line:
				continue

			packet = ElementTree.SubElement(root, "packet")
			for element in line:
				element = element.replace(" ", "")
				key, value = element.split(":")
				packet.attrib[key] = str(value)
			packet.attrib["LineNumber"] = str(lineno)

	# writing the ElementTree into the .xml file
	tree = ElementTree.ElementTree(root)
	filepath = filename + ".xml"
	tree.write(filepath)
	return filepath
