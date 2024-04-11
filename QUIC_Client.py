import select
import socket
import os
from collections import deque
from datetime import datetime
import QUIC_api as api
import copy
from tqdm import tqdm

# Recovery Algorithms
packet_number_based = True
time_based = False

# Thresholds for recovery algorithms
packet_reordering_threshold = 10
time_threshold = 0.1

# Client setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 1827  # 2048 - 221: packet size minus header size

# CIDs
client_CID = 1
server_CID = 2

# Re-transition counter
retransmit_counter = 0

# Record start time
start_time = datetime.timestamp(datetime.now())

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def time_based_recovery(packet_queue, last_ack_time):
    # Make a deep copy for packet_queue
    packet_queue_copy = copy.deepcopy(packet_queue)
    counter = 0
    for element in packet_queue_copy:
        if last_ack_time - element[2] > time_threshold and not element[1]:
            packet_queue.remove(element)
            element[2] = datetime.timestamp(datetime.now())
            packet_queue.append(element)
            sock.sendto(element[3].encode(), (server_ip, server_port))
            counter += 1
    return counter

def packet_number_based_recovery(packet_queue):
    last_ack = 0
    i = 0
    for element in reversed(packet_queue):
        if element[1]:
            last_ack = len(packet_queue) - i - 1
            break
        i += 1
    
    counter = 0
    for i in range(0, last_ack - packet_reordering_threshold):
        if packet_queue[0][1]:
            packet_queue.popleft()
        else:
            packet_queue[0][2] = datetime.timestamp(datetime.now())
            packet_queue.append(packet_queue[0])
            sock.sendto(packet_queue[0][3].encode(), (server_ip, server_port))
            counter += 1
            packet_queue.popleft()
    return counter

def receive_ACKs(packet_queue, tail):
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

                # Avoid parsing long headers
                if ack[0] == ord('1'):
                    continue

                packet_parsed = api.parse_quic_short_header_binary(ack)
                packet_payload = packet_parsed['payload']
                frame_parsed = api.parse_quic_frame(packet_payload)
                frame_data = frame_parsed['data']
                # print(f"Received ack for packet number: {frame_data}")

                # In deque change for the packet arrive in True
                for element in packet_queue:
                    if element[0] == int(frame_data):  # Packet Number
                        element[1] = True  # ACK packet arrived
                        break

            else:
                # No more ACKs available, break from the loop
                break

    except BlockingIOError:
        # No data available
        pass

    # Pop all True elements from the head of the deque until reaching false
    while packet_queue and packet_queue[0][1]:
        packet_queue.popleft()

    if time_based or (tail and len(packet_queue) <= packet_reordering_threshold*2):  # PTO for tail packets
        retransmit_counter += time_based_recovery(packet_queue, last_ack_time)

    if packet_number_based:
        retransmit_counter += packet_number_based_recovery(packet_queue)
    
    return retransmit_counter



# QUIC handshake

api.send_hello_packet(socket=sock, streamID=0, dcid=server_CID, scid=client_CID, side='Client', address=(server_ip, server_port))
print("Sent ClientHello.")

# Set time out for server hello packet
sock.settimeout(time_threshold)

while True:

    try:
        data_recv, addr = sock.recvfrom(buffer_size)
    except socket.timeout:  # On timeout, resend the handshake packet
        print("ServerHello timeout.")
        api.send_hello_packet(socket=sock, streamID=0, dcid=server_CID, scid=client_CID, side='Client', address=(server_ip, server_port))
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

filename = "alphanumeric_file.txt"
filesize = os.path.getsize(filename)
total_packets = (filesize // buffer_size) + (1 if filesize % buffer_size else 0)

# Create a packet deque
# Element format: [ packet_number , is_ACKed , send_time , packet ]
packet_queue = deque()

# Set socket to non-blocking mode
sock.setblocking(False)

# Open file and send in chunks
with open(filename, 'rb') as f:
    for packet_number in range(1, total_packets + 1):

        # Read file chunk
        bytes_read = f.read(buffer_size)

        # Create frame
        frame = api.construct_quic_frame(8, 0, 0, bytes_read)

        # Create QUIC packet
        packet = api.construct_quic_short_header_binary(server_CID, packet_number, frame)
        # print(f"packet number {packet_number} sent to server")

        packet_queue.append([packet_number, False, datetime.timestamp(datetime.now()), packet])

        # Send packet
        sock.sendto(packet.encode(), (server_ip, server_port))

        retransmit_counter += receive_ACKs(packet_queue, False)

print(f"length of queue: {len(packet_queue)}")
while len(packet_queue) > 0:
    retransmit_counter += receive_ACKs(packet_queue, True)

print("File sent successfully.")

api.send_connection_close_packet(socket=sock, streamID=0, dcid=server_CID, packet_number=total_packets+1, address=(server_ip, server_port))

print("Sending CONNECTION_CLOSE frame to server.")

try:
    while True:
        ready = select.select([sock], [], [], time_threshold)
        if ready[0]:
            data_recv, addr = sock.recvfrom(buffer_size)

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

# Open the text file in read mode
with open('alphanumeric_file.txt', 'r') as file:
    # Get the size of the file
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

print("File Size:", file_size, "bytes")
bandwidth = file_size / total_time / 8 / 1024 / 1024
print(f"Bandwidth: {bandwidth:.3f} MB/s\n")
print(f"Unique packets: {total_packets}")
print(f"Re-transmitted packets: {retransmit_counter}")