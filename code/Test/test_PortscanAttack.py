import unittest
import unittest.mock as mock

from Test.GenericTest import GenericTest
from Test.Lib import *

sha_portscan_default = 'dd28509dcc55a722c57d6b462741581d7b48024cddb8b8c89fe138661fac2b07'
sha_portscan_reverse_ports = '04f5cdab7ade15bde00f0fcf42278508da7104ac76eab543d9c4b1cbab4f67c7'
sha_portscan_shuffle_dst_ports = 'a6ef8a714da52d7608a84f50fe9dc71a3714e8b78a62be07c4e3d5509fa03d95'
sha_portscan_shuffle_src_ports = '218382e8feabea3c5a35834c9962034cdff6e0c90fafee899883a9a54bb38371'
sha_portscan_mss_value_zero = 'c3847e0a3a5abf886506dc5402fbc9a3096db2fd1df16d276d6c60c6b4b4ca5f'
sha_portscan_ttl_value_zero = 'c3847e0a3a5abf886506dc5402fbc9a3096db2fd1df16d276d6c60c6b4b4ca5f'
sha_portscan_win_value_zero = 'c3847e0a3a5abf886506dc5402fbc9a3096db2fd1df16d276d6c60c6b4b4ca5f'
sha_portscan_ip_src_random = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
sha_portscan_most_used_ip_in_list = 'c3939f30a40fa6e2164cc91dc4a7e823ca409492d44508e3edfc9d24748af0e5'
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

    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_ip_address')
    def test_portscan_most_used_ips(self, mock_most_used_ip_address):
        mock_most_used_ip_address.return_value = test_pcap_ips
        self.generic_test([['PortscanAttack']], sha_portscan_most_used_ip_in_list)


if __name__ == '__main__':
    unittest.main()
