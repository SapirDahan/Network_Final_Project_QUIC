import unittest
import time
import os
import random
import scripts
import string
import sys
sys.path.append("..")
import QUIC_api as api
sys.path.append("/Tests")

TIMEOUT = 20

class TestQUIC(unittest.TestCase):
    
    @classmethod
    def setUpClass(self):
        os.system('chmod +rwx DefaultRun.sh')
        os.system('chmod +rwx ParametersRun.sh')
        os.system('chmod +rwx TestRun.sh')
    
    def test_frame_api(self):
        for iter in range(10):
            frame_type = random.randint(0,120)
            stream_id = random.randint(0,50000)
            offset = random.randint(0,50000)
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=500))
            frame = api.construct_quic_frame(frame_type, stream_id, offset, data)

            parsed_frame = api.parse_quic_frame(frame)
            self.assertEqual(parsed_frame["frame_type"], frame_type)
            self.assertEqual(parsed_frame["stream_id"], stream_id)
            self.assertEqual(parsed_frame["offset"], offset)
            self.assertEqual(parsed_frame["data_length"], len(data))
            self.assertEqual(parsed_frame["data"], data)
        print('passed frame test')

    
    def test_short_header_api(self):
        for iter in range(10):
            dcid = random.randint(0,5000)
            packet_number = random.randint(0,999999)
            payload = api.construct_quic_frame(0,0,0,'0')
            packet = api.construct_quic_short_header_binary(dcid, packet_number, payload)

            parsed_packet = api.parse_quic_short_header_binary(packet)
            self.assertEqual(parsed_packet["header_form"], int(api.SHORT_HEADER_BIT))
            self.assertEqual(parsed_packet["key_phase_bit"], 0)
            self.assertEqual(parsed_packet["dcid"], dcid)
            self.assertEqual(parsed_packet["packet_number"], packet_number)
            self.assertEqual(parsed_packet["payload"], payload)
        print('passed short header test')

    def test_long_header_api(self):
        for iter in range(10):
            packet_type = random.randint(0,3)
            version = random.randint(0,5000)
            dcid_num = random.randint(0,5000)
            scid_num = random.randint(0,5000)
            payload = api.construct_quic_frame(0,0,0,'0')
            packet = api.construct_quic_long_header(packet_type, version, dcid_num, scid_num, payload)

            parsed_packet = api.parse_quic_long_header(packet)
            self.assertEqual(parsed_packet['packet_type'], packet_type)
            self.assertEqual(parsed_packet['type_specific_bits'], 3)
            self.assertEqual(parsed_packet['version'], version)
            self.assertEqual(parsed_packet['dcid'], format(int(dcid_num), '032b'))
            self.assertEqual(parsed_packet['scid'], format(int(scid_num), '032b'))
            self.assertEqual(parsed_packet['payload'], payload)
        print('passed long header test')

    def test_QUIC_ACK_api(self):
        for iter in range(10):
            dcid = random.randint(0, 200)
            packet_number = random.randint(0, 5000)
            ack_delay = random.randint(1, 1000)
            ack_ranges = [(1, 50), (55, 80), (300, 310)]
            ack_packet = api.construct_quic_ack_packet(dcid,packet_number,ack_delay,ack_ranges)

            parsed_packet = api.parse_quic_ack_packet(ack_packet)
            self.assertEqual(parsed_packet["header_form"], 1)
            self.assertEqual(parsed_packet["key_phase_bit"], 0)
            self.assertEqual(parsed_packet["dcid"], dcid)
            self.assertEqual(parsed_packet["packet_number"], packet_number)
            self.assertEqual(parsed_packet["ack_delay"], ack_delay)
            self.assertEqual(parsed_packet["blocks_count"], len(ack_ranges))
            self.assertListEqual(parsed_packet["ack_ranges"], ack_ranges)
        print('passed ACK packet test')

    
    def test_single_run(self):
        try:
            scripts.single_default_run(TIMEOUT)
        except TimeoutError:
            self.fail("Test execution timed out")

    def test_multiple_runs_packet_loss(self):
        packet_losses = [0,0.1,1,5,10,30]
        os.system("sudo tc qdisc add dev lo root netem loss 0%")

        for packet_loss in packet_losses:
            os.system(f'sudo tc qdisc change dev lo root netem loss {packet_loss}%')
            time.sleep(0.01)
            try:
                speed = scripts.single_default_run(TIMEOUT)
                print(f'packet loss {packet_loss}: {speed} MB/s')
            except TimeoutError:
                self.fail(f"Test execution timed out for packet loss {packet_loss}")

        os.system("sudo tc qdisc del dev lo root netem")
    
    def test_single_recovery(self):
        packet_losses = [0,0.1,1,5,10,30]
        os.system("sudo tc qdisc add dev lo root netem loss 0%")

        for packet_loss in packet_losses:
            os.system(f'sudo tc qdisc change dev lo root netem loss {packet_loss}%')
            time.sleep(0.01)
            try:
                speed = scripts.single_parameters_run(TIMEOUT, 0.1, 0)
                print(f'packet loss {packet_loss} with time only: {speed} MB/s')
            except TimeoutError:
                self.fail(f"Test execution timed out for packet loss {packet_loss} with time only")
            try:
                speed = scripts.single_parameters_run(TIMEOUT, 0, 7)
                print(f'packet loss {packet_loss} with packet only: {speed} MB/s')
            except TimeoutError:
                self.fail(f"Test execution timed out for packet loss {packet_loss} with packet only")

        os.system("sudo tc qdisc del dev lo root netem")

    def test_ack_delays(self):
        ack_delays = [0,5,20,50,100,200]
        os.system("sudo tc qdisc add dev lo root netem loss 5%")

        for ack_delay in ack_delays:
            try:
                speed = scripts.single_test_run(TIMEOUT, ack_delay)
                print(f'ack delay {ack_delay}: {speed} MB/s')
            except TimeoutError:
                self.fail(f"Test execution timed out for ack delay {ack_delay}")
        
        os.system("sudo tc qdisc del dev lo root netem")
        

if __name__ == '__main__':
    unittest.main()