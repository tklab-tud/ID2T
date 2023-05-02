import Test.ID2TAttackTest as Test


class UnitTestMiraiBotnet(Test.ID2TAttackTest):

    def test_mirai_basic(self):
        self.order_test([['MiraiBotnet_x_Log4shell']])

    def test_mirai_mac_source(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'mac.src=00:19:36:v4:77:ey']])

    def test_mirai_mac_destination(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'mac.dst=02:42:ac:14:00:05']])

    def test_mirai_ip_source(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'ip.src=213.146.212.41']])

    def test_mirai_ip_destination(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'ip.dst=104.12.0.44']])

    def test_miria_cnc_server_ip(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'cnc.server.ip=101.33.33.2']])

    def test_mirai_http_flood_target_ip(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'http.flood.target.ip=101.11.3.0']])

    def test_mirai_loader_server_ip(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'loader.server.ip=101.101.33.2']])

    def test_mirai_packets_per_second(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'packets.per-second=400']])

    def test_mirai_time_after_first_stage(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'time.after.first.stage=40']])

    def test_mirai_time_after_second_stage(self):
        self.order_test([['MiraiBotnet_x_Log4shell', 'time.after.second.stage=40']])