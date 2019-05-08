import unittest
import TMLib.TMUnitTest as lib

import TMLib.ReWrapper as ReWrap
import TMLib.Definitions as TMdef


class TMReWrapper(unittest.TestCase):

    def test_init(self):
        statistics = {}
        globalRWdict = {}
        conversationRWdict = {}
        packetRWdict = {}

        rw = ReWrap.ReWrapper(statistics, globalRWdict, conversationRWdict, packetRWdict)

        self.assertTrue( rw.data_dict[TMdef.GLOBAL] is globalRWdict )
        self.assertTrue( rw.data_dict[TMdef.CONVERSATION] is conversationRWdict )
        self.assertTrue( rw.data_dict[TMdef.PACKET] is packetRWdict )

        self.assertTrue( rw.statistics is statistics )

    def test_enqueue_preprocessing_function(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()
        
        ### Test single function
        i = 0
        output = []
        for protocol in lib.recognized_protocols:
            rw.enqueue_preprocessing_function(protocol, lib.mock_function(i))
            output.append(i)
            i += 1

        self.assertTrue( len(lib.recognized_protocols) == len(output) )
        self.assertTrue( len(lib.recognized_protocols) == len(rw.preprocess_dict.keys()) )

        # _function_count = list(set([len(preprocess) for preprocess in rw.preprocess_dict.items()]))
        # self.assertTrue( len(_function_count) == 1 and _function_count[0] == 1 )

        for i in range(len(lib.recognized_protocols)):
            p = lib.recognized_protocols[i]
            queue = rw.preprocess_dict[p]
            self.assertTrue(len(queue) == 1)
            self.assertTrue( queue[0]() == output[i] )

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        ### Test proper order for 3
        i = 0
        output = []
        for protocol in lib.recognized_protocols:
            for _ in range(3):
                rw.enqueue_preprocessing_function(protocol, lib.mock_function(i))
                output.append(i)
                i += 1

        self.assertTrue( len(lib.recognized_protocols)*3 == len(output) )
        self.assertTrue( len(lib.recognized_protocols) == len(rw.preprocess_dict.keys()) )

        j = 0
        for i in range(len(lib.recognized_protocols)):
            p = lib.recognized_protocols[i]
            for k in range(3):
                queue = rw.preprocess_dict[p]
                self.assertTrue(len(queue) == 3)
                self.assertTrue( queue[k]() == output[j] )
                j += 1

    def test_enqueue_processing_function(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()
        
        ### Test single function
        i = 0
        output = []
        for protocol in lib.recognized_protocols:
            rw.enqueue_processing_function(protocol, lib.mock_function(i))
            output.append(i)
            i += 1

        self.assertTrue( len(lib.recognized_protocols) == len(output) )
        self.assertTrue( len(lib.recognized_protocols) == len(rw.process_dict.keys()) )

        # _function_count = list(set([len(preprocess) for preprocess in rw.process_dict.items()]))
        # self.assertTrue( len(_function_count) == 1 and _function_count[0] == 1 )

        for i in range(len(lib.recognized_protocols)):
            p = lib.recognized_protocols[i]
            queue = rw.process_dict[p]
            self.assertTrue(len(queue) == 1)
            self.assertTrue( queue[0]() == output[i] )

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        ### Test proper order for 3
        i = 0
        output = []
        for protocol in lib.recognized_protocols:
            for _ in range(3):
                rw.enqueue_processing_function(protocol, lib.mock_function(i))
                output.append(i)
                i += 1

        self.assertTrue( len(lib.recognized_protocols)*3 == len(output) )
        self.assertTrue( len(lib.recognized_protocols) == len(rw.process_dict.keys()) )

        j = 0
        for i in range(len(lib.recognized_protocols)):
            p = lib.recognized_protocols[i]
            for k in range(3):
                queue = rw.process_dict[p]
                self.assertTrue(len(queue) == 3)
                self.assertTrue( queue[k]() == output[j] )
                j += 1

    def test_enqueue_postprocessing_function(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()
        
        ### Test single function
        i = 0
        output = []
        for protocol in lib.recognized_protocols:
            rw.enqueue_postprocessing_function(protocol, lib.mock_function(i))
            output.append(i)
            i += 1

        self.assertTrue( len(lib.recognized_protocols) == len(output) )
        self.assertTrue( len(lib.recognized_protocols) == len(rw.postprocess_dict.keys()) )

        # _function_count = list(set([len(preprocess) for preprocess in rw.postprocess_dict.items()]))
        # self.assertTrue( len(_function_count) == 1 and _function_count[0] == 1 )

        for i in range(len(lib.recognized_protocols)):
            p = lib.recognized_protocols[i]
            queue = rw.postprocess_dict[p]
            self.assertTrue(len(queue) == 1)
            self.assertTrue( queue[0]() == output[i] )

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        ### Test proper order for 3
        i = 0
        output = []
        for protocol in lib.recognized_protocols:
            for _ in range(3):
                rw.enqueue_postprocessing_function(protocol, lib.mock_function(i))
                output.append(i)
                i += 1

        self.assertTrue( len(lib.recognized_protocols)*3 == len(output) )
        self.assertTrue( len(lib.recognized_protocols) == len(rw.postprocess_dict.keys()) )

        j = 0
        for i in range(len(lib.recognized_protocols)):
            p = lib.recognized_protocols[i]
            queue = rw.postprocess_dict[p]
            self.assertTrue(len(queue) == 3)
            for k in range(3):
                self.assertTrue( queue[k]() == output[j] )
                j += 1

    def test_set_timestamp_generator(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        for i in range(3):
            rw.set_timestamp_generator(lib.mock_function(i))
            self.assertTrue( rw.timestamp_function() == i )


    def test_set_backup_timestamp_generator(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        for i in range(3):
            rw.set_backup_timestamp_generator(lib.mock_function(i))
            self.assertTrue( rw.data_dict[TMdef.GLOBAL]['generate_timestamp_function_alt']() == i )


    def test_enqueue_timestamp_postprocessing_function(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()
        
        ### Test single function
        output = [1]
        rw.enqueue_timestamp_postprocess(lib.mock_function(1))


        self.assertTrue(len(rw.timestamp_postprocess) == 1)
        self.assertTrue( rw.timestamp_postprocess[0]() == output[0] )

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        ### Test proper order for 3
        output = []
        for i in range(3):
            rw.enqueue_timestamp_postprocess(lib.mock_function(i))
            output.append(i)

        queue = rw.timestamp_postprocess
        self.assertTrue(len(queue) == 3)
        for i in range(3):
            self.assertTrue( queue[i]() == output[i] )


    def test_set_timestamp_next_pkt(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        for i in range(3):
            rw.set_timestamp_next_pkt(i)
            self.assertTrue( rw.data_dict[TMdef.CONVERSATION]['timestamp_next_pkt'] == i )
            self.assertTrue( rw.get_timestamp_next_pkt() == i )

    def test_set_timestamp_shift(self):

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        for i in range(3):
            rw.set_timestamp_shift(i)
            self.assertTrue( rw.data_dict[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_shift'] == i )
            self.assertTrue( rw.get_timestamp_shift() == i )

    def test_timestamp_generation(self):

        class Pkt(object):
            def __init__(self, _time):
                self.time = _time

        def base_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp*10

        def post_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp+1

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        rw.set_timestamp_generator(base_f)
        for i in range(3):
            rw.enqueue_timestamp_postprocess(post_f)

        i = 0
        tp = Pkt(0)
        for _ in range(10):
            i *= 10
            i *= 3
            tp.time = rw.generate_timestamp(tp, rw.data_dict)
            if i == 0:
                self.assertTrue( tp.time == 0 )
            else:
                self.assertTrue( tp.time == i )


    def test_timestamp_generation_in_place(self):

        class Pkt(object):
            def __init__(self, _time):
                self.time = _time

        def base_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp

        def post_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        rw.set_timestamp_generator(base_f)

        i = 0
        tp = Pkt(0)
        for _ in range(10):
            tp.time = rw.generate_timestamp(tp, rw.data_dict)
            self.assertTrue( tp.time == i )

        ## Postprocess added
        rw, _, _, _, _ = lib.build_mock_rewrapper()

        rw.set_timestamp_generator(base_f)
        for i in range(3):
            rw.enqueue_timestamp_postprocess(post_f)

        i = 0
        tp = Pkt(0)
        for _ in range(10):
            tp.time = rw.generate_timestamp(tp, rw.data_dict)
            self.assertTrue( tp.time == i )


    def test_timestamp_generation_erronous(self):

        class Pkt(object):
            def __init__(self, _time):
                self.time = _time

        def base_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp - 1

        def base_f_2(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp + 10

        def post_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp - 1

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        rw.set_timestamp_generator(base_f)
        for i in range(3):
            rw.enqueue_timestamp_postprocess(post_f)

        i = 0
        tp = Pkt(0)
        for _ in range(10):
            tp.time = rw.generate_timestamp(tp, rw.data_dict)
            if i == 0:
                self.assertTrue( tp.time == 0 )
            else:
                self.assertTrue( tp.time == i )

        ## Postprocess added
        rw, _, _, _, _ = lib.build_mock_rewrapper()

        rw.set_timestamp_generator(base_f)
        for i in range(3):
            rw.enqueue_timestamp_postprocess(post_f)

        i = 0
        tp = Pkt(0)
        for _ in range(10):
            tp.time = rw.generate_timestamp(tp, rw.data_dict)
            if i == 0:
                self.assertTrue( tp.time == 0 )
            else:
                self.assertTrue( tp.time == i )
# ,None, None, None, None, None

        rw.set_timestamp_generator(base_f_2)

        rw.data_dict[TMdef.CONVERSATION]['previous_timestamp_new'] = 1
        rw.data_dict[TMdef.CONVERSATION]['previous_timestamp_old'] = 1
        i = 6
        tp.time = i
        tp.time = rw.generate_timestamp(tp, rw.data_dict)
        i = i + 10 - 3
        self.assertTrue( tp.time == i )


    def test_digest(self):

        class Pkt(object):
            def __init__(self, _time=None, _value=None, _payload=None):
                self.time = _time
                self.value = _value
                self.payload = _payload

        def base_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp * 10

        def post_f(packet, data, previous_timestamp_old, previous_timestamp_new, current_timestamp_old, new_timestamp):
            return new_timestamp + 1

        def mock_transf(i):
            def m_t(packet, data):
                packet.value += i
            return m_t

        ReWrap.recognized_protocols.append(Pkt)

        rw, _, _, _, _ = lib.build_mock_rewrapper()

        ### Test single function
        output = []
        for i in range(3):
            rw.enqueue_preprocessing_function( Pkt, mock_transf(i) )
            rw.enqueue_processing_function( Pkt, mock_transf(i) )
            rw.enqueue_postprocessing_function( Pkt, mock_transf(i) )
            output.append(i)

        rw.set_timestamp_generator(base_f)
        for i in range(3):
            rw.enqueue_timestamp_postprocess(post_f)

        values = [100, 200, 300]
        j = 0
        _tf = sum(output)*3
        for i in range(1, 11):
            p_1 = Pkt(_value=values[j%len(values)])
            p_2 = Pkt(_value=values[(j+1)%len(values)], _payload=p_1)
            p_3 = Pkt(_time=i, _value=values[(j+2)%len(values)], _payload=p_2)

            rw.digest(p_3)

            self.assertTrue( p_1.value ==  values[j%len(values)]+_tf )
            self.assertTrue( p_2.value ==  values[(j+1)%len(values)]+_tf )
            self.assertTrue( p_3.value ==  values[(j+2)%len(values)]+_tf )

            if i <= 1:
                self.assertTrue( p_3.time == 1 )
            else:
                self.assertTrue( p_3.time == (i*10)+3 )

            j = (j+1)%len(values)

