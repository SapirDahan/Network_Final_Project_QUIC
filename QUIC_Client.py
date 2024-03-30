import select
import socket
import os
from collections import deque
from datetime import datetime
import QUIC_api as api

# Recovery Algorithms
packet_number_based = False
time_based = True

# Packet reordering threshold
packet_reordering_threshold = 0

# Time threshold
time_threshold = 10

# Client setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 803  # 1024 - 221: packet size minus header size

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# QUIC handshake

"""
---Construct ClientHello frame---
frame type 6 is being used for handshake
stream id is 0
offset is 0
data is 'ClientHello'
"""
client_hello_frame = api.construct_quic_frame(6, 0, 0, "ClientHello")

"""
---Construct ClientHello packet---
packet type is 0
version is 1
dcid (destination connection id) is '0002'
scid (source connection id) is '0001'
payload is client_hello_frame
"""
client_hello_packet = api.construct_quic_long_header(0, 1, '0002', '0001', client_hello_frame)
sock.sendto(client_hello_packet.encode(), (server_ip, server_port))
print("Sent ClientHello.")

while True:
    data_recv, addr = sock.recvfrom(buffer_size)

    # parse the received data
    parsed_packet = api.parse_quic_long_header(data_recv)
    parsed_frame = api.parse_quic_frame(parsed_packet['payload'])
    if parsed_frame['data'].decode() == 'ServerHello':
        print("Received ServerHello.\nHandshake Completed.")
        break

filename = "alphanumeric_file.txt"
filesize = os.path.getsize(filename)
total_packets = (filesize // buffer_size) + (1 if filesize % buffer_size else 0)

print("Total packets: " + str(total_packets))

# Send initial packet with filename and total packets
initial_packet = f"{filename},{total_packets}".encode()
sock.sendto(initial_packet, (server_ip, server_port))

# Create a packet deque
packet_queue = deque()

# Set socket to non-blocking mode
sock.setblocking(False)


# Open file and send in chunks
with open(filename, 'rb') as f:
    for packet_number in range(1, total_packets + 1):
        # Read file chunk
        bytes_read = f.read(buffer_size)

        # Create frame
        frame = api.construct_quic_frame(0, 0, 0, bytes_read)

        # Create QUIC packet
        packet = api.construct_quic_short_header_binary(2, packet_number, frame)
        #print(f"packet number {packet_number} sent to server")

        packet_queue.append([packet_number, False, datetime.timestamp(datetime.now()), packet])

        # Send packet
        sock.sendto(packet.encode(), (server_ip, server_port))

        # Try to receive ACKs
        try:
            while True:
                ready = select.select([sock], [], [], 0)
                if ready[0]:
                    ack, _ = sock.recvfrom(1024)
                    packet_parsed = api.parse_quic_short_header_binary(ack)
                    packet_payload = packet_parsed['payload']
                    frame_parsed = api.parse_quic_frame(packet_payload)
                    frame_data = frame_parsed['data']
                    #print(f"Received ack for packet number: {frame_data}")

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

        if time_based:
            # Make a deep copy for packet_queue
            packet_queue_copy = packet_queue.copy()
            for element in packet_queue_copy:
                if datetime.timestamp(datetime.now()) - element[2] > time_threshold and not element[1]:
                    packet_queue.remove(element)
                    element[2] = datetime.timestamp(datetime.now())
                    packet_queue.append(element)
                    print(f"Packet {element[0]} ack timeout")
                    sock.sendto(element[3].encode(), (server_ip, server_port))

print("File sent successfully.")
sock.close()

# print the deque without the frame
for packet in packet_queue:
    print(packet[:3])
