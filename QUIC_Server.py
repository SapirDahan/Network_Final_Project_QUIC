import socket
import QUIC_api as api

# Server setup
server_ip = '127.0.0.1'
server_port = 9997
buffer_size = 2048

# CIDs
server_CID = 2
client_CID = None  # receive client_CID at handshake

# Timeout for the server to wait for retransmission before continuing
retransmission_timeout = 0.05

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
        server_hello_packet = api.construct_quic_long_header(0, 1, client_CID, server_CID, server_hello_frame)
        sock.sendto(server_hello_packet.encode(), addr)
        print("Sent ServerHello.\n")

        # Set timeout for receiving ClientHello again
        sock.settimeout(retransmission_timeout)
        try:
            while True:
                data_recv, addr = sock.recvfrom(buffer_size)

                # Checking if the received packet is ClientHello
                if data_recv[0] == ord('0'):
                    sock.settimeout(0)
                    break

        except socket.timeout:
            print("ServerHello timeout. Waiting for retransmission of ClientHello...")
            sock.settimeout(0)
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
        # Creating ACK frame
        ack_frame = api.construct_quic_frame(2, 0, 0, str(packet_number))

        # Create ACK packet and send to client
        ack_packet = api.construct_quic_short_header_binary(client_CID, ack_packet_number, ack_frame)
        ack_packet_number += 1
        sock.sendto(ack_packet.encode(), addr)


if not timeout_flag:
    # Send CONNECTION_CLOSE massage to the client
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
    dcid is 1 (client)
    The number packet is 0
    The frame is connection_close_frame
    """
    connection_close_packet = api.construct_quic_short_header_binary(client_CID, 0, connection_close_frame)
    # a = api.parse_quic_short_header_binary(connection_close_packet)
    # b = api.parse_quic_frame(a['payload'])
    # print(b['data'])
    sock.sendto(connection_close_packet.encode(), addr)

# Generate statistics
print(f"Sent {ack_packet_number - 1} ack packets to client.")

sock.close()

print("Connection closed")