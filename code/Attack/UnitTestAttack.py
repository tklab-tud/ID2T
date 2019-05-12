import Attack.AttackParameters as atkParam
import Attack.BaseAttack as BaseAttack

class UnitTestAttack(BaseAttack.BaseAttack):

    def __init__(self):

        super(Test, self).__init__("UnitTest Attack", "Used for Unit Testing of the toolkit.'",
                                  "Any")

        self.pkt_num = 0

        self.supported_params.update({
            atkParam.Parameter.INJECT_AT_TIMESTAMP: atkParam.ParameterTypes.TYPE_FLOAT
        })


    def init_params(self):
        """
        Initialize all required parameters taking into account user supplied values. If no value is supplied,
        or if a user defined query is supplied, use a statistics object to do the calculations.
        A call to this function requires a call to 'set_statistics' first.
        """
        pass


    def generate_attack_packets(self):
        """
        Creates the attack packets.
        """
        pass


    def generate_attack_pcap(self):
        pass

