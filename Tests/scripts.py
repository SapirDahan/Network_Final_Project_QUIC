import time
import os
import signal


def run_default_script():
    os.system("./DefaultRun.sh")
    time.sleep(0.001)


def run_parameters_script(time_threshold, packet_threshold):
    os.system(f"./ParametersRun.sh {packet_threshold} {time_threshold}")
    time.sleep(0.001)


def single_default_run(timeout):
    signal.alarm(timeout)
    run_default_script()

    with open('client_output.txt', 'r') as file:
        for line in file:
            if "Bandwidth:" in line:
                return float(line.split(" ")[1].strip())


def single_parameters_run(timeout, time_threshold, packet_threshold):
    signal.alarm(timeout)
    run_parameters_script(time_threshold, packet_threshold)

    with open('client_output.txt', 'r') as file:
        for line in file:
            if "Bandwidth:" in line:
                return float(line.split(" ")[1].strip())
