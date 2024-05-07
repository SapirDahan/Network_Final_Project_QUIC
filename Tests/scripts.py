import time
import os
import signal


def run_default_script():
    os.system("./DefaultRun.sh")
    time.sleep(0.001)


def run_parameters_script(time_threshold, packet_threshold):
    os.system(f"./ParametersRun.sh {packet_threshold} {time_threshold}")
    time.sleep(0.001)

def run_test_script(ack_delay):
    os.system(f"./TestRun.sh {ack_delay}")
    time.sleep(0.001)


def parse_speed():
    with open('client_output.txt', 'r') as file:
        for line in file:
            if "Bandwidth:" in line:
                return float(line.split(" ")[1].strip())


def single_default_run(timeout):
    signal.alarm(timeout)
    run_default_script()
    return parse_speed()

def single_parameters_run(timeout, time_threshold, packet_threshold):
    signal.alarm(timeout)
    run_parameters_script(time_threshold, packet_threshold)
    return parse_speed()

def single_test_run(timeout, ack_delay):
    signal.alarm(timeout)
    run_test_script(ack_delay)
    return parse_speed()
