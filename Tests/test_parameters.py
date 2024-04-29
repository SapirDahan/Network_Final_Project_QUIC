import unittest
import time
import os
import scripts


class TestQUIC(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        os.system('chmod +rwx DefaultRun.sh')
        os.system('chmod +rwx ParametersRun.sh')

    def test_ranges(self):
        packet_based_ranges = [7,10,12]
        time_based_ranges = [0.01,0.1]
        packet_losses = [0,0.1,1,5]

        os.system("sudo tc qdisc add dev lo root netem loss 0%")
        for packet_loss in packet_losses:
            os.system(f'sudo tc qdisc change dev lo root netem loss {packet_loss}%')
            time.sleep(0.01)
            print(f'running packet loss: {packet_loss}')

            packet_thresholds_speeds = {}
            for packet_threshold in packet_based_ranges:
                try:
                    speed = scripts.single_parameters_run(timeout=15, time_threshold=0,
                                                          packet_threshold=packet_threshold)
                    packet_thresholds_speeds[packet_threshold] = speed
                except TimeoutError:
                    self.fail(
                        f"Test execution timed out for packet loss {packet_loss} with only packet based: {packet_threshold}")
            packet_thresholds_speeds = sorted(packet_thresholds_speeds.items(), key=lambda x: x[1])

            time_thresholds_speeds = {}
            for time_threshold in time_based_ranges:
                try:
                    speed = scripts.single_parameters_run(timeout=15, time_threshold=time_threshold, packet_threshold=0)
                    time_thresholds_speeds[time_threshold] = speed
                except TimeoutError:
                    self.fail(
                        f"Test execution timed out for packet loss {packet_loss} with only time based: {time_threshold}")
            time_thresholds_speeds = sorted(time_thresholds_speeds.items(), key=lambda x: x[1])

            both_thresholds_speeds = {}
            for packet_threshold in packet_based_ranges:
                for time_threshold in time_based_ranges:
                    try:
                        speed = scripts.single_parameters_run(timeout=15, time_threshold=time_threshold,
                                                              packet_threshold=packet_threshold)
                        both_thresholds_speeds[(packet_threshold, time_threshold)] = speed
                    except TimeoutError:
                        self.fail(
                            f"Test execution timed out for packet loss {packet_loss} with time based: {time_threshold} and packet based: {packet_threshold}")
            both_thresholds_speeds = sorted(both_thresholds_speeds.items(), key=lambda x: x[1])

            print('Time:')
            print(time_thresholds_speeds[:])
            print('Number:')
            print(packet_thresholds_speeds[:])
            print('Both:')
            print(both_thresholds_speeds[:])

        os.system('sudo tc qdisc del dev lo root netem')


if __name__ == '__main__':
    unittest.main()
