import select
import socket
import os
from collections import deque
from datetime import datetime
import QUIC_api as api

# Recovery Algorithms
packet_number_based = True
time_based = True

# Packet reordering threshold
packet_reordering_threshold = 10

# Time threshold
time_threshold = 0.1

# Client setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 1827  # 2048 - 221: packet size minus header size

# Record start time
start_time = datetime.timestamp(datetime.now())

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

# Set time out for server hello packet
sock.settimeout(time_threshold)

while True:

    try:
        data_recv, addr = sock.recvfrom(buffer_size)
    except socket.timeout:
        print("ServerHello timeout.")
        break
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

# Send initial packet with filename and total packets
# initial_packet = f"{filename},{total_packets}".encode()
# sock.sendto(initial_packet, (server_ip, server_port))

# Create a packet deque
packet_queue = deque()

# Set socket to non-blocking mode
sock.setblocking(False)

# Re-transition counter
retransmit_counter = 0

# Open file and send in chunks
with open(filename, 'rb') as f:
    for packet_number in range(1, total_packets + 1):
        # Read file chunk
        bytes_read = f.read(buffer_size)

        # Create frame
        frame = api.construct_quic_frame(8, 0, 0, bytes_read)

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
                    ack, _ = sock.recvfrom(2048)

                    # Avoid parsing long headers
                    if ack[0] == ord('1'):
                        continue

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
                    #print(f"Packet {element[0]} ack timeout")
                    sock.sendto(element[3].encode(), (server_ip, server_port))
                    retransmit_counter += 1

        last_ack = 0
        i = 0
        if packet_number_based:
            for element in reversed(packet_queue):
                if element[1]:
                    last_ack = len(packet_queue) - i - 1
                    break
                i += 1

            for i in range(0, last_ack - packet_reordering_threshold):
                if packet_queue[0][1]:
                    packet_queue.popleft()
                else:
                    packet_queue[0][2] = datetime.timestamp(datetime.now())
                    packet_queue.append(packet_queue[0])
                    sock.sendto(packet_queue[0][3].encode(), (server_ip, server_port))
                    retransmit_counter += 1
                    packet_queue.popleft()

while len(packet_queue) > 0:
    ready = select.select([sock], [], [], 0)
    if ready[0]:
        ack, _ = sock.recvfrom(2048)
        packet_parsed = api.parse_quic_short_header_binary(ack)
        packet_payload = packet_parsed['payload']
        frame_parsed = api.parse_quic_frame(packet_payload)
        frame_data = frame_parsed['data']

        # In deque change for the packet arrive in True
        for element in packet_queue:
            if element[0] == int(frame_data):  # Packet Number
                element[1] = True  # ACK packet arrived
                break

        # Make a deep copy for packet_queue
        packet_queue_copy = packet_queue.copy()
        for element in packet_queue_copy:
            if datetime.timestamp(datetime.now()) - element[2] > time_threshold and not element[1]:
                packet_queue.remove(element)
                element[2] = datetime.timestamp(datetime.now())
                packet_queue.append(element)
                sock.sendto(element[3].encode(), (server_ip, server_port))

            # Pop all True elements from the head of the deque until reaching false
            while packet_queue and packet_queue[0][1]:
                packet_queue.popleft()



print("File sent successfully.")

# Send CONNECTION_CLOSE massage to the server

"""
---Construct CONNECTION_CLOSE frame---
frame type 0x1c is being used for connection close
stream id is 0
offset is 0
data is 'CONNECTION_CLOSE'
"""
connection_close_frame = api.construct_quic_frame(0x1c, 0, 0, "CONNECTION_CLOSE")

"""
---Construct CONNECTION_CLOSE packet---
dcid is 2 (server)
The number packet is total_packets + 1
The frame is connection_close_frame
"""
connection_close_packet = api.construct_quic_short_header_binary(2, total_packets + 1, connection_close_frame)

sock.sendto(connection_close_packet.encode(), (server_ip, server_port))

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
    bandwidth = file_size/total_time/8/1024/1024
    print(f"Bandwidth: {bandwidth:.3f} MB/s\n")

print(f"Unique packets: {total_packets}")
print(f"Re-transmitted packets: {retransmit_counter}")
