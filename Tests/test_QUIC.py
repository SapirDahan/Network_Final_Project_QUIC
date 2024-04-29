import unittest
import time
import os
import random
import scripts
import sys
sys.path.append("..")
import QUIC_api as api
sys.path.append("/Tests")


class TestQUIC(unittest.TestCase):
    
    @classmethod
    def setUpClass(self):
        os.system('chmod +rwx DefaultRun.sh')
        os.system('chmod +rwx ParametersRun.sh')


    def test_QUIC_ACK_api(self):
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

    
    def test_single_run(self):
        try:
            scripts.single_default_run(15)
        except TimeoutError:
            self.fail("Test execution timed out")

    def test_multiple_runs_packet_loss(self):
        packet_losses = [0,0.1,1,5,10,30]
        os.system("sudo tc qdisc add dev lo root netem loss 0%")

        for packet_loss in packet_losses:
            os.system(f'sudo tc qdisc change dev lo root netem loss {packet_loss}%')
            time.sleep(0.01)
            try:
                speed = scripts.single_default_run(15)
                print(f'packet loss {packet_loss}: {speed} MB/s')
            except TimeoutError:
                self.fail(f"Test execution timed out for packet loss {packet_loss}")

        os.system("sudo tc qdisc del dev lo root netem")
        

if __name__ == '__main__':
    unittest.main()