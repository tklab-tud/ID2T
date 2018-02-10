import unittest
import unittest.mock as mock

import ID2TLib.Statistics as Statistics
import Test.GenericTest as GenericTest
import ID2TLib.TestLibrary as Lib

sha_basic_ddos = '52c5df968818155f6aa143d4f7eed8fe4014df595d9e561cc9c898842790bbc8'
sha_num_attackers_ddos = 'e4e1acf27cb87445be802db7a4cad31fcce1a14221b0c65af040d14c8f30b4d1'
# FIXME: get hash for currently broken test
sha_dest_mac_length_zero_ddos = ''
sha_mss_none_ddos = '52c5df968818155f6aa143d4f7eed8fe4014df595d9e561cc9c898842790bbc8'

"""
Name                             Stmts   Miss  Cover   Missing
--------------------------------------------------------------------------------------------
Attack/DDoSAttack.py                124     7   94%    70, 105-106, 120, 123, 141, 187
"""


class UnitTestDDoS(GenericTest.GenericTest):

    @mock.patch.object(Statistics.Statistics, 'get_rnd_win_size', side_effect=Lib.get_win_size)
    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    def test_basic(self, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack']],
                          sha_basic_ddos)

    @mock.patch.object(Statistics.Statistics, 'get_rnd_win_size', side_effect=Lib.get_win_size)
    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    def test_num_attackers(self, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack', 'attackers.count=5']],
                          sha_num_attackers_ddos)

    # FIXME: currently returns 'ERROR: 'NoneType' object has no attribute 'route'
    #@mock.patch.object(Statistics.Statistics, 'get_rnd_win_size', side_effect=get_win_size)
    #@mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=get_attacker_config)
    #@mock.patch('ID2TLib.Statistics.Statistics.get_mac_address', return_value='')
    #def test_dest_mac_length_zero(self, mock_dest_mac, mock_get_attacker_config, mock_get_rnd_win_size):
    #    self.generic_test([['DDoSAttack']], sha_dest_mac_length_zero_ddos)

    @mock.patch.object(Statistics.Statistics, 'get_rnd_win_size', side_effect=Lib.get_win_size)
    @mock.patch('ID2TLib.Utility.get_attacker_config', side_effect=Lib.get_attacker_config)
    @mock.patch('ID2TLib.Statistics.Statistics.get_most_used_mss', return_value=None)
    def test_mss_none(self, mock_mss, mock_get_attacker_config, mock_get_rnd_win_size):
        self.generic_test([['DDoSAttack']], sha_mss_none_ddos)


if __name__ == '__main__':
    unittest.main()
