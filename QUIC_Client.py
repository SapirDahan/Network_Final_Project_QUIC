import socket
import os

import QUIC_api as api

# Recovery Algorithms
packet_number_based = False
time_based = False

# Packet reordering threshold
packet_reordering_threshold = 0

# Time threshold
time_threshold = 0

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

# Open file and send in chunks
with open(filename, 'rb') as f:
    for packet_number in range(1, total_packets + 1):
        # Read file chunk
        bytes_read = f.read(buffer_size)

        # Create frame
        frame = api.construct_quic_frame(0, 0, 0, bytes_read)

        # Create QUIC packet
        packet = api.construct_quic_short_header_binary(2, packet_number, frame)
        print(f"the length is: {len(packet)}")

        # Prepend packet number as 4-byte header
        #packet = packet_number.to_bytes(4, byteorder='big') + bytes_read

        # Send packet
        sock.sendto(packet.encode(), (server_ip, server_port))

print("File sent successfully.")
sock.close()
