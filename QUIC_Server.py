import socket
import QUIC_api as api

# Server setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 1024

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((server_ip, server_port))

print(f"Server listening on {server_ip}:{server_port}")

# QUIC handshake

while True:
    data_recv, addr = sock.recvfrom(buffer_size)

    # parse the received data
    parsed_packet = api.parse_quic_long_header(data_recv)
    parsed_frame = api.parse_quic_frame(parsed_packet['payload'])

    if parsed_frame['data'].decode() == "ClientHello":
        print("Received ClientHello.")

        """
        ---Construct ClientHello frame---
        frame type 6 is being used for handshake
        stream id is 0
        offset is 0
        data is 'ServerHello'
        """
        server_hello_frame = api.construct_quic_frame(6, 0, 0, "ServerHello")

        """
        ---Construct ClientHello packet---
        packet type is 0
        version is 1
        dcid (destination connection id) is '0001'
        scid (source connection id) is '0002'
        payload is client_hello_frame
        """
        server_hello_packet = api.construct_quic_long_header(0, 1, '0001', '0002', server_hello_frame)
        sock.sendto(server_hello_packet.encode(), addr)
        print("Sent ServerHello.\n")
        break


# Receive initial packet with filename and total packets
data, addr = sock.recvfrom(buffer_size)
filename, total_packets = data.decode().split(',')
total_packets = int(total_packets)
print(f"Receiving file: {filename}, total packets: {total_packets}")

# Open file for writing
with open('received_'+filename, 'wb') as f:
    for expected_packet in range(1, total_packets + 1):
        # Receive packet
        packet, addr = sock.recvfrom(buffer_size)
        packet_number = int.from_bytes(packet[:4], byteorder='big')
        if packet_number == expected_packet:
            # Write packet data to file, skipping the 4-byte header
            f.write(packet[4:])
        else:
            print(f"Packet {packet_number} out of order. Expected {expected_packet}")

print("File received successfully.")
sock.close()
