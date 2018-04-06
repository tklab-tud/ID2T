import unittest
import xml.etree.ElementTree
import os.path
import sys

from Test.TestUtil import PcapComparator, ID2TExecution


class RegressionTest(unittest.TestCase):
    REGRESSION_DIRECTORY = "../resources/test/Botnet/regression_files"
    REGRESSION_DIRECTORY_ID2T_RELATIVE = "resources/test/Botnet/regression_files"
    ID2T_RELATIVE_TO_LOCAL_PREFIX = "../"
    VERBOSE = False
    META_FILE = "fileinfo.xml"

    def test_regression(self):
        self.printed_newline = False
        config_location = self.REGRESSION_DIRECTORY + os.sep + self.META_FILE
        xml_root = xml.etree.ElementTree.parse(config_location).getroot()
        comparator = PcapComparator()

        for test in xml_root.getchildren():
            self.assertXMLTagHasAttribute(test, "seed", "<test>s needs a seed-attribute")
            self.assertXMLTagHasAttribute(test, "outfile", "<test>s needs a outfile-attribute")
            self.assertXMLTagHasAttribute(test, "infile", "<test>s needs a infile-attribute")
            self.assertXMLTagHasAttribute(test, "name", "<test>s needs a name-attribute")

            params = []
            for param in test.getchildren():
                self.assertEqual(param.tag, "param", "<test>-children must be <params>s")
                self.assertIsNotNone(param.get("key"), "<param> needs a key-attribute")
                self.assertIsNotNone(param.get("value"), "<param> needs a value-attribute")

                params.append("%s=%s" % (param.get("key"), param.get("value")))

            infile = os.path.join(self.REGRESSION_DIRECTORY_ID2T_RELATIVE, test.get("infile"))
            outfile = os.path.join(self.REGRESSION_DIRECTORY, test.get("outfile"))

            execution = ID2TExecution(infile, seed=test.get("seed"))
            self.print_warning("Running %s with command:" % test.get("name"))
            self.print_warning(execution.get_run_command(params))
            execution.run(params)

            new_file = self.ID2T_RELATIVE_TO_LOCAL_PREFIX + os.sep + execution.get_pcap_filename()
            old_file = outfile

            try:
                comparator.compare_files(new_file, old_file)
            except AssertionError as e:
                execution.cleanup()
                raise AssertionError("Test failed") from e

            self.print_warning("Test passed")

    def assertXMLTagHasAttribute(self, tag, attribute, msg=None):
        self.assertIsNotNone(tag.get(attribute), msg)

    def print_warning(self, *text):
        if self.VERBOSE:
            if not self.printed_newline:
                print("\n", file=sys.stderr)
                self.printed_newline = True
            print(*text, file=sys.stderr)
