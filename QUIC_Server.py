import socket
from datetime import datetime, timedelta
import QUIC_api as api
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--delay", type=int, default=20, help="The maximum time a receiver might delay sending an ACK")
args = parser.parse_args()

# Server setup
SERVER_IP = '127.0.0.1'
SERVER_PORT = 9997
BUFFER_SIZE = 2048

# CIDs
SERVER_CID = 2
CLIENT_CID = None  # receive client_CID at handshake

# Timeout for the server to wait for retransmission of clientHello before continuing
RETRANSMISSION_TIMEOUT = 0.01

# The maximum time a receiver might delay sending an ACK
ACK_DELAY = args.delay  # in ms

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))

print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

# QUIC handshake
first_received = False

while True:

    try:
        data_recv, addr = sock.recvfrom(BUFFER_SIZE)
    except BlockingIOError:
        continue

    # Checking if short header (not handshake packet) due to client hello packet loss
    if data_recv[0] == ord(api.SHORT_HEADER_BIT):
        if CLIENT_CID is None:
            raise Exception("Client attempted to send packets before connection was established")
        first_received = True
        break

    # Parse the received data
    parsed_packet = api.parse_quic_long_header(data_recv)
    CLIENT_CID = int(parsed_packet['scid'])
    parsed_frame = api.parse_quic_frame(parsed_packet['payload'])

    if parsed_frame['data'].decode() == "ClientHello":
        print(f"Received ClientHello from CID: {CLIENT_CID}.")
        api.send_hello_packet(socket=sock, streamID=0, dcid=CLIENT_CID, scid=SERVER_CID, side='Server', address=addr)
        print("Sent ServerHello.\n")

        # Set timeout for receiving ClientHello again
        sock.settimeout(RETRANSMISSION_TIMEOUT)
        try:
            while True:
                data_recv, addr = sock.recvfrom(BUFFER_SIZE)

                # Checking if the received packet is ClientHello
                if data_recv[0] == ord(api.SHORT_HEADER_BIT):
                    first_received = True
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
TIMEOUT = 10
timeout_flag = False
# Set time out for the server socket. If no packet received in "timeout" seconds then we close the connection
sock.settimeout(TIMEOUT)
frames = []

while True:
    # Receive packet

    try:
        if first_received:  # if the first packet was already received while waiting
            first_received = False
            packet = data_recv
        else:
            packet, addr = sock.recvfrom(BUFFER_SIZE)

    except socket.timeout:
        timeout_flag = True
        print("Timeout reached.")
        break

    # parse the packet to receive the data
    packet_parsed = api.parse_quic_short_header_binary(packet)
    packet_number = packet_parsed['packet_number']
    packet_payload = packet_parsed['payload']
    frame_parsed = api.parse_quic_frame(packet_payload)
    frame_data = frame_parsed['data']
    if frame_parsed['offset'] not in frames:
        frames.append(frame_parsed['offset'])

    if frame_parsed['frame_type'] == 0x1c:
        print("File received successfully.")
        print("Received CONNECTION_CLOSE frame from client.\nSending CONNECTION_CLOSE frame to client.")
        break

    if frame_parsed['frame_type'] == 0x08:
        # Delay the ACK for ACK_DELAY ms in order to receive more packets and ACK them all at once
        packets_received = [packet_number]  # initialize a list of received packet numbers
        ack_delay_time = (datetime.now() + timedelta(milliseconds=ACK_DELAY)).timestamp()

        while True:
            curr_timeout = ack_delay_time - datetime.now().timestamp()  # Update the end of the delay
            if curr_timeout < 0:
                break
            sock.settimeout(curr_timeout)
            try:
                packet, addr = sock.recvfrom(BUFFER_SIZE)

                # Parse the packet to receive data
                packet_parsed = api.parse_quic_short_header_binary(packet)
                packet_number = packet_parsed['packet_number']
                frame_parsed = api.parse_quic_frame(packet_parsed['payload'])
                if frame_parsed['offset'] not in frames:
                    frames.append(frame_parsed['offset'])

                if packet_number not in packets_received:
                    packets_received.append(packet_number)

            except socket.timeout:
                break
            except BlockingIOError:
                pass
        sock.settimeout(TIMEOUT)

        # Compress the list of received packet numbers into a list of ACK ranges
        ack_ranges = []
        i = 0
        while i < len(packets_received):
            left = packets_received[i]
            while i < len(packets_received)-1 and packets_received[i]+1 == packets_received[i+1]:
                i += 1
            right = packets_received[i]
            ack_ranges.append((left, right))
            i += 1

        # Create ACK packet and send to client
        ack_packet = api.construct_quic_ack_packet(CLIENT_CID, ack_packet_number, ACK_DELAY, ack_ranges)
        ack_packet_number += 1
        sock.sendto(ack_packet.encode(), addr)


if not timeout_flag:
    api.send_connection_close_packet(socket=sock, streamID=0, dcid=CLIENT_CID, packet_number=0, address=addr)

# Generate statistics
print(f"Sent {ack_packet_number - 1} ack packets to client.")
print(f"Received {len(frames)} frames")

sock.close()

print("Connection closed")