import select
import socket
import os
from collections import deque
from datetime import datetime
import QUIC_api as api
import argparse

parser = argparse.ArgumentParser(
    description="Enter the thresholds for time based recovery and packet number based recovery or leave them out to "
                "use the default threshold. To turn off a specific recovery, set its threshold to 0. Note that you "
                "need at least one active recovery algorithm")
parser.add_argument("-t", "--time", type=float, default=0.1,
                    help="Value of time_threshold (default: 0.1). Enter 0 to turn off time based recovery.")
parser.add_argument("-n", "--number", type=int, default=7,
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
PTO_TIMEOUT = 0.2
THRESHOLDS = (PACKET_REORDERING_THRESHOLD, TIME_THRESHOLD, PTO_TIMEOUT)

# Client setup
SERVER_IP = '127.0.0.1'
SERVER_PORT = 9997
SERVER_ADDRESS = (SERVER_IP, SERVER_PORT)
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


# QUIC handshake

api.send_hello_packet(socket=sock, streamID=0, dcid=SERVER_CID, scid=CLIENT_CID, side='Client',
                      address=SERVER_ADDRESS)
print("Sent ClientHello.")

# Set time out for server hello packet
HANDSHAKE_TIMEOUT = 0.005
sock.settimeout(HANDSHAKE_TIMEOUT)

while True:

    try:
        data_recv, addr = sock.recvfrom(BUFFER_SIZE)
    except socket.timeout:  # On timeout, resend the handshake packet
        print("ServerHello timeout.")
        api.send_hello_packet(socket=sock, streamID=0, dcid=SERVER_CID, scid=CLIENT_CID, side='Client',
                              address=SERVER_ADDRESS)
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
        sock.sendto(packet.encode(), SERVER_ADDRESS)

        # Update the current packet number
        current_packet_number += 1

        retrans_count,  time_count, number_count, new_packet_number = api.receive_ACKs(sock,SERVER_ADDRESS,packet_queue, False,current_packet_number, *THRESHOLDS)
        retransmit_counter += retrans_count
        time_retransmit_counter += time_count
        packet_number_retransmit_counter += number_count
        current_packet_number = new_packet_number

while len(packet_queue) > 0:
    retrans_count,  time_count, number_count, new_packet_number = api.receive_ACKs(sock,SERVER_ADDRESS,packet_queue, True,current_packet_number, *THRESHOLDS)
    retransmit_counter += retrans_count
    time_retransmit_counter += time_count
    packet_number_retransmit_counter += number_count
    current_packet_number = new_packet_number
print("File sent successfully.")

api.send_connection_close_packet(socket=sock, streamID=0, dcid=SERVER_CID, packet_number=total_packets + 1,
                                 address=SERVER_ADDRESS)

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
print(f"Time retransmit counter: {time_retransmit_counter} ")
print(f"Packet number retransmit counter: {packet_number_retransmit_counter}")
