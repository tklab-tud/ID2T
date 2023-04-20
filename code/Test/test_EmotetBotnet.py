import Test.ID2TAttackTest as Test


class UnitTestEmotetBotnet(Test.ID2TAttackTest):

    def test_emotet_basic(self):
        self.order_test([['EmotetBotnet']])

    def test_emotet_mac_source(self):
        self.order_test([['EmotetBotnet', 'mac.src=00:19:36:v4:77:ey']])

    def test_emotet_ip_source(self):
        self.order_test([['EmotetBotnet', 'ip.src=213.146.212.41']])

    def test_emotet_packets_per_second(self):
        self.order_test([['EmotetBotnet', 'packets.per-second=400']])

    def test_emotet_spam_bot_activity(self):
        self.order_test([['EmotetBotnet', 'spam.bot.activity=False']])