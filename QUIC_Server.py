import socket
import QUIC_api as api
from datetime import datetime, timedelta

# Server setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 2048

# CIDs
server_CID = 2
client_CID = None  # receive client_CID at handshake

# Timeout for the server to wait for retransmission before continuing
retransmission_timeout = 0.05

# bla bla bla
ACK_DELAY = 20  # in ms

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((server_ip, server_port))

print(f"Server listening on {server_ip}:{server_port}")

# QUIC handshake

while True:

    try:
        data_recv, addr = sock.recvfrom(buffer_size)
    except BlockingIOError:
        continue

    # Checking if short header (not handshake packet) due to client hello packet loss
    if data_recv[0] == ord('0'):
        break

    # Parse the received data
    parsed_packet = api.parse_quic_long_header(data_recv)
    client_CID = int(parsed_packet['scid'])
    parsed_frame = api.parse_quic_frame(parsed_packet['payload'])

    if parsed_frame['data'].decode() == "ClientHello":
        print(f"Received ClientHello from CID: {client_CID}.")
        api.send_hello_packet(socket=sock, streamID=0, dcid=client_CID, scid=server_CID, side='Server', address=addr)
        print("Sent ServerHello.\n")

        # Set timeout for receiving ClientHello again
        sock.settimeout(retransmission_timeout)
        try:
            while True:
                data_recv, addr = sock.recvfrom(buffer_size)

                # Checking if the received packet is ClientHello
                if data_recv[0] == ord('0'):
                    sock.settimeout(None)
                    break

        except socket.timeout:
            print("ServerHello timeout. Waiting for retransmission of ClientHello...")
            sock.settimeout(None)
            continue

        break

print("Handshake completed.")

# Main Loop
ack_packet_number = 1
timeout = 10
timeout_flag = False
# Set time out for the server socket. If no packet received in "timeout" seconds then we close the connection
sock.settimeout(timeout)

while True:
    # Receive packet

    try:
        packet, addr = sock.recvfrom(buffer_size)

    except socket.timeout:
        timeout_flag = True
        print("Timeout reached.")
        break

    packet_parsed = api.parse_quic_short_header_binary(packet)
    packet_number = packet_parsed['packet_number']
    packet_payload = packet_parsed['payload']
    frame_parsed = api.parse_quic_frame(packet_payload)
    frame_data = frame_parsed['data']

    if frame_parsed['frame_type'] == 0x1c:
        print("File received successfully.")
        print("Received CONNECTION_CLOSE frame from client.\nSending CONNECTION_CLOSE frame to client.")
        break

    if frame_parsed['frame_type'] == 0x08:
        packets_received = [packet_number]
        ack_delay_time = (datetime.now() + timedelta(milliseconds=ACK_DELAY)).timestamp()

        while True:
            curr_timeout = ack_delay_time - datetime.now().timestamp()
            if curr_timeout < 0:
                break
            sock.settimeout(curr_timeout)
            try:
                packet, addr = sock.recvfrom(buffer_size)

                packet_parsed = api.parse_quic_short_header_binary(packet)
                packet_number = packet_parsed['packet_number']

                if packet_number not in packets_received:
                    packets_received.append(packet_number)

            except socket.timeout:
                break
            except BlockingIOError:
                pass
        sock.settimeout(timeout)

        ack_ranges = []
        i = 0
        while i < len(packets_received):
            left = packets_received[i]
            while i < len(packets_received)-1 and packets_received[i]+1 == packets_received[i+1]:
                i += 1
            right = packets_received[i]
            ack_ranges.append((left,right))
            i += 1

        if len(ack_ranges) > 0:
            # Create ACK packet and send to client
            ack_packet = api.construct_quic_ack_packet(client_CID, ack_packet_number, ACK_DELAY, ack_ranges)
            parsed_ack_packet = api.parse_quic_ack_packet(ack_packet)  # TODO: delete this line
            ack_packet_number += 1
            sock.sendto(ack_packet.encode(), addr)


if not timeout_flag:
    api.send_connection_close_packet(socket=sock, streamID=0, dcid=client_CID, packet_number=0, address=addr)

# Generate statistics
print(f"Sent {ack_packet_number - 1} ack packets to client.")

sock.close()

print("Connection closed")