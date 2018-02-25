import unittest
import inspect

import ID2TLib.Controller as Ctrl
import ID2TLib.TestLibrary as Lib
import scapy.utils as pcr


class ID2TAttackTest(unittest.TestCase):
    """
    Generic Test Class for ID2T attacks based on unittest.TestCase.
    """

    def checksum_test(self, attack_args, sha256_checksum, seed=5, cleanup=True, pcap=Lib.test_pcap,
                      flag_write_file=False, flag_recalculate_stats=False, flag_print_statistics=False,
                      attack_sub_dir=True, test_sub_dir=True):
        """
        Runs the attack against a given sha256 checksum.

        :param attack_args: A list of attacks with their attack parameters (as defined in Controller.process_attacks).
        :param sha256_checksum: The checksum to verify the result pcap.
        :param seed: A random seed to keep random values static (care for count and order of random generation).
        :param cleanup: Clean up attack output after testing.
        :param pcap: The input pcap for the attack.
        :param flag_write_file: Writes the statistics to a file.
        :param flag_recalculate_stats: Forces the recalculation of statistics.
        :param flag_print_statistics: Prints the statistics on the terminal.
        :param attack_sub_dir: create sub-directory for each attack-class if True
        :param test_sub_dir: create sub-directory for each test-function/case if True
        """

        controller = Ctrl.Controller(pcap_file_path=pcap, do_extra_tests=False)
        controller.load_pcap_statistics(flag_write_file, flag_recalculate_stats, flag_print_statistics)
        controller.process_attacks(attack_args, [[seed]])

        caller_function = inspect.stack()[1].function

        try:
            self.assertEqual(sha256_checksum, Lib.get_sha256(controller.pcap_dest_path))
        except self.failureException:
            Lib.rename_test_result_files(controller, caller_function, attack_sub_dir, test_sub_dir)
            raise

        if cleanup:
            Lib.clean_up(controller)
        else:
            Lib.rename_test_result_files(controller, caller_function, attack_sub_dir, test_sub_dir)

    def order_test(self, attack_args, seed=None, cleanup=True, pcap=Lib.test_pcap,
                   flag_write_file=False, flag_recalculate_stats=False, flag_print_statistics=False,
                   attack_sub_dir=True, test_sub_dir=True):
        """
        Checks if the result of an attack includes all packets in correct order.

        :param attack_args: A list of attacks with their attack parameters (as defined in Controller.process_attacks).
        :param seed: A random seed to keep random values static (care for count and order of random generation).
        :param cleanup: Clean up attack output after testing.
        :param pcap: The input pcap for the attack.
        :param flag_write_file: Writes the statistics to a file.
        :param flag_recalculate_stats: Forces the recalculation of statistics.
        :param flag_print_statistics: Prints the statistics on the terminal.
        :param attack_sub_dir: create sub-directory for each attack-class if True
        :param test_sub_dir: create sub-directory for each test-function/case if True
        """

        controller = Ctrl.Controller(pcap_file_path=pcap, do_extra_tests=False)
        controller.load_pcap_statistics(flag_write_file, flag_recalculate_stats, flag_print_statistics)
        controller.process_attacks(attack_args, [[seed]])

        caller_function = inspect.stack()[1].function

        try:
            path = controller.pcap_dest_path
            file = pcr.RawPcapReader(path)
            packet_a = file.read_packet()
            packet_b = file.read_packet()
            i = 0

            while packet_b is not None:

                time_a = packet_a[2][0:2]
                time_b = packet_b[2][0:2]

                if time_a[0] > time_b[0]:
                    file.close()
                    self.fail("Packet order incorrect at: " + str(i+1) + "-" + str(i+2) +
                              ". Current time: " + str(time_a) + " Next time: " + str(time_b))
                elif time_a[0] == time_b[0]:
                    if time_a[1] > time_b[1]:
                        file.close()
                        self.fail("Packet order incorrect at: " + str(i + 1) + "-" + str(i + 2) +
                                  ". Current time: " + str(time_a) + " Next time: " + str(time_b))

                packet_a = packet_b
                packet_b = file.read_packet()
                i += 1

            file.close()

        except self.failureException:
            Lib.rename_test_result_files(controller, caller_function, attack_sub_dir, test_sub_dir)
            raise

        if cleanup:
            Lib.clean_up(controller)
        else:
            Lib.rename_test_result_files(controller, caller_function, attack_sub_dir, test_sub_dir)
