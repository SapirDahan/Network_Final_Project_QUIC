import socket

# Server setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 1024

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((server_ip, server_port))

print(f"Server listening on {server_ip}:{server_port}")

# Receive initial packet with filename and total packets
data, addr = sock.recvfrom(buffer_size)
filename, total_packets = data.decode().split(',')
total_packets = int(total_packets)
print(f"Receiving file: {filename}, total packets: {total_packets}")

# Open file for writing
with open(filename, 'wb') as f:
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