import unittest
import unittest.mock as mock

import ID2TLib.TestLibrary as Lib
from Test.GenericTest import GenericTest

sha_portscan_default = '6af539fb9f9a28f84a5c337a07dbdc1a11885c5c6de8f9a682bd74b89edc5130'
sha_portscan_reverse_ports = '1c03342b7b94fdd1c9903d07237bc5239ebb7bd77a3dd137c9c378fa216c5382'
sha_portscan_shuffle_dst_ports = '40485e47766438425900b787c4cda4ad1b5cd0d233b80f38bd45b5a88b70a797'
sha_portscan_shuffle_src_ports = '48578b45e18bdbdc0a9f3f4cec160ccb58839250348ec4d3ec44c1b15da248de'
sha_portscan_mss_value_zero = '8d32476a89262b78118a68867fff1d45c81f8ffb4970201f9d5ee3dfd94ba58a'
sha_portscan_ttl_value_zero = 'ff8cf15d8e59856e0c6e43d81fa40180ebf2127042f376217cc2a20e4f21726e'
sha_portscan_win_value_zero = 'b2fcbf72190ac3bf12192d0d7ee8c09ef87adb0d94a2610615ca76d8b577bbfb'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'

"""
CURRENT COVERAGE
Name                             Stmts   Miss  Cover   Missing (lines)
---------------------------------------------------------------------------
Attack/PortscanAttack.py           146      6    96%   73, 108-109, 158, 211, 238
"""
# TODO: get 100% coverage


class UnitTestPortscanAttack(GenericTest):

    def test_portscan_default(self):
        self.generic_test([['PortscanAttack']], sha_portscan_default)

    def test_portscan_reverse_ports(self):
        self.generic_test([['PortscanAttack', 'port.dst.order-desc=1']], sha_portscan_reverse_ports)

    def test_portscan_shuffle_dst_ports(self):
        self.generic_test([['PortscanAttack', 'port.dst.shuffle=1']], sha_portscan_shuffle_dst_ports)

    def test_portscan_shuffle_src_ports(self):
        self.generic_test([['PortscanAttack', 'port.src.shuffle=1']], sha_portscan_shuffle_src_ports)

    @mock.patch('ID2TLib.Statistics.Statistics.get_mss_distribution', return_value='')
    def test_portscan_mss_length_zero(self, mock_mss_dis):
        self.generic_test([['PortscanAttack']], sha_portscan_mss_value_zero)

    @mock.patch('ID2TLib.Statistics.Statistics.get_ttl_distribution', return_value='')
    def test_portscan_ttl_length_zero(self, mock_ttl_dis):
        self.generic_test([['PortscanAttack']], sha_portscan_ttl_value_zero)

    @mock.patch('ID2TLib.Statistics.Statistics.get_win_distribution', return_value='')
    def test_portscan_win_length_zero(self, mock_win_dis):
        self.generic_test([['PortscanAttack']], sha_portscan_win_value_zero)


if __name__ == '__main__':
    unittest.main()
