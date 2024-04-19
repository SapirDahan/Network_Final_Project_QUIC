import unittest
import time
from collections import OrderedDict
import os
import signal

def run_default_script():
    os.system("./DefaultRun.sh")
    
def run_parameters_script(time_threshold, packet_threshold):
    os.system(f"./ParametersRun.sh {packet_threshold} {time_threshold}")

def single_default_run(timeout):
    # Set a timeout of 15 seconds
    signal.alarm(timeout)
    run_default_script()
        
    with open('client_output.txt', 'r') as file:
        for line in file:
            if "Bandwidth:" in line:
                return float(line.split(" ")[1].strip())

def single_parameters_run(timeout, time_threshold, packet_threshold):
    # Set a timeout of 15 seconds
    signal.alarm(timeout)
    run_parameters_script(time_threshold, packet_threshold)
        
    with open('client_output.txt', 'r') as file:
        for line in file:
            if "Bandwidth:" in line:
                return float(line.split(" ")[1].strip())


class TestQUIC(unittest.TestCase):
    
    @classmethod
    def setUpClass(self):
        os.system('chmod +x DefaultRun.sh')
        os.system('chmod +x ParametersRun.sh')

    
    def test_single_run(self):
        try:
            single_default_run(15)
        except TimeoutError:
            self.fail("Test execution timed out")
    
    def test_multiple_runs_packet_loss(self):
        packet_losses = [0,0.1,1,5,10,30]
        os.system("sudo tc qdisc add dev lo root netem loss 0%")

        for packet_loss in packet_losses:
            os.system(f'sudo tc qdisc change dev lo root netem loss {packet_loss}%')
            time.sleep(0.01)
            try:
                speed = single_default_run(15)
                print(f'packet loss {packet_loss}: {speed} MB/s')
            except TimeoutError:
                self.fail(f"Test execution timed out for packet loss {packet_loss}")

        os.system("sudo tc qdisc del dev lo root netem")
        

    # def test_ranges(self):
    #     packet_based_ranges = range(1,20)
    #     time_based_ranges = [0.01,0.02,0.05,0.07,0.08,0.1,0.15]
    #     packet_losses = [0,0.1,1,5,10,30]
        
    #     os.system("sudo tc qdisc add dev lo root netem loss 0%")
    #     for packet_loss in packet_losses:
    #         os.system(f'sudo tc qdisc change dev lo root netem loss {packet_loss}%')
    #         time.sleep(0.01)

    #         packet_thresholds_speeds = {}
    #         for packet_threshold in packet_based_ranges:
    #             try:
    #                 speed = single_parameters_run(timeout=15, time_threshold=0, packet_threshold=packet_threshold)
    #                 packet_thresholds_speeds[packet_threshold] = speed
    #             except TimeoutError:
    #                 self.fail(f"Test execution timed out for packet loss {packet_loss} with only packet based: {packet_threshold}")
    #         packet_thresholds_speeds = sorted(packet_thresholds_speeds.items(), key=lambda x: x[1])

    #         time_thresholds_speeds = {}
    #         for time_threshold in time_based_ranges:
    #             try:
    #                 speed = single_parameters_run(timeout=15, time_threshold=time_threshold, packet_threshold=0)
    #                 time_thresholds_speeds[time_threshold] = speed
    #             except TimeoutError:
    #                 self.fail(f"Test execution timed out for packet loss {packet_loss} with only time based: {time_threshold}")
    #         time_thresholds_speeds = sorted(time_thresholds_speeds.items(), key=lambda x: x[1])



    #         print('Time:')
    #         print(time_thresholds_speeds[0][0])
    #         print('Number:')
    #         print(packet_thresholds_speeds[0][0])

    #     os.system('sudo tc qdisc del dev lo root netem')
        

if __name__ == '__main__':
    unittest.main()