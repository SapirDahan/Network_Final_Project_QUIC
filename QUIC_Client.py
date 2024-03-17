import socket
import os

# Client setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 1020  # 4 bytes less than the server to account for packet number

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

filename = "alphanumeric_file.txt"
filesize = os.path.getsize(filename)
total_packets = (filesize // buffer_size) + (1 if filesize % buffer_size else 0)

# Send initial packet with filename and total packets
initial_packet = f"{filename},{total_packets}".encode()
sock.sendto(initial_packet, (server_ip, server_port))

# Open file and send in chunks
with open(filename, 'rb') as f:
    for packet_number in range(1, total_packets + 1):
        # Read file chunk
        bytes_read = f.read(buffer_size)
        # Prepend packet number as 4-byte header
        packet = packet_number.to_bytes(4, byteorder='big') + bytes_read
        # Send packet
        sock.sendto(packet, (server_ip, server_port))

print("File sent successfully.")
sock.close()