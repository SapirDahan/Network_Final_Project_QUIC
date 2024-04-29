import select
import socket
import os
from collections import deque
from datetime import datetime
import QUIC_api as api
import copy
import argparse

parser = argparse.ArgumentParser(
    description="Enter the thresholds for time based recovery and packet number based recovery or leave them out to "
                "use the default threshold. To turn off a specific recovery, set its threshold to 0. Note that you "
                "need at least one active recovery algorithm")
parser.add_argument("-t", "--time", type=float, default=0.1,
                    help="Value of time_threshold (default: 0.1). Enter 0 to turn off time based recovery.")
parser.add_argument("-n", "--number", type=int, default=10,
                    help="packet_reordering_threshold (default: 10). Enter 0 to turn off packet number based recovery.")
args = parser.parse_args()

if args.time == 0 and args.number == 0:
    raise Exception("Need to have at least one recovery algorithm")

# Recovery Algorithms
PACKET_NUMBER_BASED = args.number != 0
TIME_BASED = args.time != 0

# Thresholds for recovery algorithms
PACKET_REORDERING_THRESHOLD = args.number
TIME_THRESHOLD = args.time
if not PACKET_NUMBER_BASED:
    PACKET_REORDERING_THRESHOLD = 10
if not TIME_THRESHOLD:
    TIME_THRESHOLD = 0.1
PTO_TIMEOUT = 0.05

# Client setup
SERVER_IP = '127.0.0.1'
SERVER_PORT = 9997
BUFFER_SIZE = 1827  # 2048 - 221: packet size minus header size

# CIDs
CLIENT_CID = 1
SERVER_CID = 2

# Retransmition counters
retransmit_counter = 0
time_retransmit_counter = 0
packet_number_retransmit_counter = 0

# Current packet number
current_packet_number = 0

# Record start time
start_time = datetime.timestamp(datetime.now())

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def time_based_recovery(packet_queue, last_ack_time):
    global current_packet_number
    # Make a deep copy for packet_queue
    packet_queue_copy = copy.deepcopy(packet_queue)
    counter = 0
    for element in packet_queue_copy:
        if last_ack_time - element[2] > TIME_THRESHOLD and not element[1]:
            packet_queue.remove(element)

            # Assign the packet a new packet number and append it to the queue
            element[0] = current_packet_number
            lost_packet = api.parse_quic_short_header_binary(element[3])
            lost_packet['packet_number'] = current_packet_number
            element[3] = api.construct_quic_short_header_binary(lost_packet["dcid"], lost_packet["packet_number"],
                                                                lost_packet["payload"])
            element[2] = datetime.timestamp(datetime.now())
            packet_queue.append(element)

            # Resend the packet
            sock.sendto(element[3].encode(), (SERVER_IP, SERVER_PORT))
            counter += 1
            current_packet_number += 1
    return counter


def packet_number_based_recovery(packet_queue):
    last_ack = 0
    i = 0
    #
    for element in reversed(packet_queue):
        if element[1]:
            last_ack = len(packet_queue) - i - 1
            break
        i += 1

    global current_packet_number
    counter = 0
    for i in range(0, last_ack - PACKET_REORDERING_THRESHOLD):
        if packet_queue[0][1]:
            packet_queue.popleft()
        else:
            # Update the lost packet in the queue
            packet_queue[0][0] = current_packet_number
            lost_packet = api.parse_quic_short_header_binary(packet_queue[0][3])
            lost_packet['packet_number'] = current_packet_number
            packet_queue[0][3] = api.construct_quic_short_header_binary(lost_packet["dcid"],
                                                                        lost_packet["packet_number"],
                                                                        lost_packet["payload"])
            packet_queue[0][2] = datetime.timestamp(datetime.now())

            # Append it to the queue and send it again
            packet_queue.append(packet_queue[0])
            sock.sendto(packet_queue[0][3].encode(), (SERVER_IP, SERVER_PORT))

            counter += 1
            current_packet_number += 1
            packet_queue.popleft()
    return counter


def PTO_recovery(packet_queue):
    global current_packet_number
    # Make a deep copy for packet_queue
    packet_queue_copy = copy.deepcopy(packet_queue)
    counter = 0
    for element in packet_queue_copy:
        if datetime.now().timestamp() - element[2] > PTO_TIMEOUT and not element[1]:
            packet_queue.remove(element)

            element[0] = current_packet_number
            lost_packet = api.parse_quic_short_header_binary(element[3])
            lost_packet['packet_number'] = current_packet_number
            element[3] = api.construct_quic_short_header_binary(lost_packet["dcid"], lost_packet["packet_number"],
                                                                lost_packet["payload"])
            element[2] = datetime.timestamp(datetime.now())

            packet_queue.append(element)
            sock.sendto(element[3].encode(), (SERVER_IP, SERVER_PORT))
            counter += 1
            current_packet_number += 1
    return counter


def receive_ACKs(packet_queue, tail):
    global time_retransmit_counter
    global packet_number_retransmit_counter
    retransmit_counter = 0

    last_ack_time = -1
    if tail:
        last_ack_time = datetime.timestamp(datetime.now())

    # Try to receive ACKs
    try:
        while True:
            ready = select.select([sock], [], [], 0)
            if ready[0]:
                ack, _ = sock.recvfrom(2048)
                last_ack_time = datetime.timestamp(datetime.now())

                # Avoid parsing short headers
                if ack[0] == ord('0'):
                    continue

                ack_packet = api.parse_quic_ack_packet(ack)
                ack_ranges = ack_packet['ack_ranges']
                curr_block = 0
                for element in packet_queue:
                    if curr_block >= len(ack_ranges):
                        break
                    if ack_ranges[curr_block][0] <= element[0] <= ack_ranges[curr_block][1]:
                        element[1] = True
                    elif element[0] > ack_ranges[curr_block][1]:
                        curr_block += 1

            else:
                # No more ACKs available, break from the loop
                break

    except BlockingIOError:
        # No data available
        pass

    # Pop all True elements from the head of the deque until reaching false
    while packet_queue and packet_queue[0][1]:
        packet_queue.popleft()

    if TIME_BASED:
        count = time_based_recovery(packet_queue, last_ack_time)
        retransmit_counter += count
        time_retransmit_counter += count

    if PACKET_NUMBER_BASED:
        count = packet_number_based_recovery(packet_queue)
        retransmit_counter += count
        packet_number_retransmit_counter += count

    if tail and len(packet_queue) <= max(PACKET_REORDERING_THRESHOLD, 10) * 2:  # PTO for tail packets
        retransmit_counter += PTO_recovery(packet_queue)

    return retransmit_counter


# QUIC handshake

api.send_hello_packet(socket=sock, streamID=0, dcid=SERVER_CID, scid=CLIENT_CID, side='Client',
                      address=(SERVER_IP, SERVER_PORT))
print("Sent ClientHello.")

# Set time out for server hello packet
sock.settimeout(TIME_THRESHOLD)

while True:

    try:
        data_recv, addr = sock.recvfrom(BUFFER_SIZE)
    except socket.timeout:  # On timeout, resend the handshake packet
        print("ServerHello timeout.")
        api.send_hello_packet(socket=sock, streamID=0, dcid=SERVER_CID, scid=CLIENT_CID, side='Client',
                              address=(SERVER_IP, SERVER_PORT))
        retransmit_counter += 1
        print("Sent ClientHello.")
        continue
    except BlockingIOError:
        continue

    # parse the received data
    parsed_packet = api.parse_quic_long_header(data_recv)
    parsed_frame = api.parse_quic_frame(parsed_packet['payload'])
    if parsed_frame['data'].decode() == 'ServerHello':
        print("Received ServerHello.\nHandshake Completed.")
        break

# Cancel socket timeout for normal UDP operation
sock.settimeout(None)

FILE_PATH = os.path.abspath(os.path.dirname(__file__))+"/alphanumeric_file.txt"
print(FILE_PATH)
# Open the text file in read mode
with open(FILE_PATH, 'r') as file:
    # Get the size of the file
    file.seek(0, os.SEEK_END)
    FILE_SIZE = file.tell()
    file.seek(0)
total_packets = (FILE_SIZE // BUFFER_SIZE) + (1 if FILE_SIZE % BUFFER_SIZE else 0)

# Create a packet deque
# Element format: [ packet_number , is_ACKed , send_time , packet ]
packet_queue = deque()

# Set socket to non-blocking mode
sock.setblocking(False)

# Open file and send in chunks
curr_offest = 0
with open(FILE_PATH, 'rb') as f:
    for i in range(1, total_packets + 1):
        # Read file chunk
        bytes_read = f.read(BUFFER_SIZE)

        # Create frame
        frame = api.construct_quic_frame(8, 0, curr_offest, bytes_read)
        curr_offest += len(bytes_read)

        # Create QUIC packet
        packet = api.construct_quic_short_header_binary(SERVER_CID, current_packet_number, frame)
        # print(f"packet number {packet_number} sent to server")

        packet_queue.append([current_packet_number, False, datetime.timestamp(datetime.now()), packet])

        # Send packet
        sock.sendto(packet.encode(), (SERVER_IP, SERVER_PORT))

        # Update the current packet number
        current_packet_number += 1

        retransmit_counter += receive_ACKs(packet_queue, False)

print(f"length of queue: {len(packet_queue)}")
while len(packet_queue) > 0:
    retransmit_counter += receive_ACKs(packet_queue, True)

print("File sent successfully.")

api.send_connection_close_packet(socket=sock, streamID=0, dcid=SERVER_CID, packet_number=total_packets + 1,
                                 address=(SERVER_IP, SERVER_PORT))

print("Sending CONNECTION_CLOSE frame to server.")

try:
    while True:
        ready = select.select([sock], [], [], TIME_THRESHOLD)
        if ready[0]:
            data_recv, addr = sock.recvfrom(BUFFER_SIZE)

            # parse the received data
            parsed_packet = api.parse_quic_short_header_binary(data_recv)
            parsed_frame = api.parse_quic_frame(parsed_packet['payload'])
            if parsed_frame['frame_type'] == 0x1c:
                print("Received CONNECTION_CLOSE from the server.")
                break
        else:
            print("CONNECTION_CLOSE time out reached.")
            break

except BlockingIOError:
    # No data available
    pass

sock.close()

print("Connection closed.\n")

# Record end time
end_time = datetime.timestamp(datetime.now())

# Generate statistics

total_time = end_time - start_time
print(f"Total time is: {total_time:.6f} seconds")

print("File Size:", FILE_SIZE, "bytes")
bandwidth = FILE_SIZE / total_time / 8 / 1024 / 1024
print(f"Bandwidth: {bandwidth:.3f} MB/s\n")
print(f"Unique packets: {total_packets}")
print(f"Re-transmitted packets: {retransmit_counter}")
print(f"Final packet number: {current_packet_number - 1}")
print(f"time retransmit counter: {time_retransmit_counter} ")
print(f"packet number retransmit counter: {packet_number_retransmit_counter}")
