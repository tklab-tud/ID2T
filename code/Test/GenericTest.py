import unittest
import inspect

import ID2TLib.Controller as Ctrl
import ID2TLib.TestLibrary as Lib


class GenericTest(unittest.TestCase):

    def generic_test(self, attack_args, sha_checksum, seed=5, cleanup=True, pcap=Lib.test_pcap, flag_write_file=False,
                     flag_recalculate_stats=False, flag_print_statistics=False, attack_sub_dir=True, test_sub_dir=True):
        # TODO: move seed to attacks
        controller = Ctrl.Controller(pcap_file_path=pcap, do_extra_tests=False)
        controller.load_pcap_statistics(flag_write_file, flag_recalculate_stats, flag_print_statistics)
        attack_args[0].append("seed=" + str(seed))
        controller.process_attacks(attack_args)

        caller_function = inspect.stack()[1].function

        try:
            self.assertEqual(sha_checksum, Lib.get_sha256(controller.pcap_dest_path))
        except self.failureException:
            Lib.rename_test_result_files(controller, caller_function, attack_sub_dir, test_sub_dir)
            raise

        if cleanup:
            Lib.clean_up(controller)
        else:
            Lib.rename_test_result_files(controller, caller_function, attack_sub_dir, test_sub_dir)
