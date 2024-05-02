from datetime import datetime
import copy
import select

def construct_quic_long_header(packet_type, version, dcid_num, scid_num, payload):
    """
    Constructs a simplified QUIC long header from string inputs.
    Note: In real implementations, these would be binary operations.

    Parameters:
    - packet_type: the type of the packet
    - version: the QUIC version this packet is in
    - dcid_num: the destination connection ID as an integer
    - scid_num: the source connection ID as an integer
    - payload: the frame or frames that are sent with the packet

    """
    # Header Form (1 bit) + Fixed Bit (1 bit) + Long Packet Type (2 bits) + Reserved Bits (2 bits) + Packet Number Length (2 bits)
    # Here, we use a simple string representation for these fields.
    header_bits = '1' + '1' + format(packet_type, '02b') + '00' + '11'

    # Version (32 bits)
    version_str = format(version, '032b')

    # Convert numerical connection IDs to string representation with leading zeros
    dcid = format(int(dcid_num), '032b')
    scid = format(int(scid_num), '032b')

    # Connection ID Lengths and IDs
    dcid_length = format(len(dcid), '08b')
    scid_length = format(len(scid), '08b')

    # Payload Length (assuming payload is a string for simplicity)
    payload_length = format(len(payload), '016b')

    # Constructing the full header
    quic_long_header = header_bits + version_str + dcid_length + dcid + scid_length + scid + payload_length + payload

    return quic_long_header


def parse_quic_long_header(quic_long_header):
    """
    Parses a simplified QUIC long header.
    Note: In real implementations, these would be binary operations.
    """
    # Extracting parts of the header
    packet_type = int(quic_long_header[2:4], 2)
    type_specific_bits = int(quic_long_header[4:8], 2)
    version = int(quic_long_header[8:40], 2)
    dcid_length = int(quic_long_header[40:48], 2)
    dcid_end = 48 + dcid_length
    dcid = quic_long_header[48:dcid_end]
    scid_length = int(quic_long_header[dcid_end:dcid_end + 8], 2)
    scid_end = dcid_end + 8 + scid_length
    scid = quic_long_header[dcid_end + 8:scid_end]

    payload_length_bits = scid_end + 16  # Assuming fixed length for simplicity
    payload = quic_long_header[payload_length_bits:]

    return {
        'packet_type': packet_type,
        'type_specific_bits': type_specific_bits,
        'version': version,
        'dcid': dcid,
        'scid': scid,
        'payload': payload
    }


def construct_quic_short_header_binary(dcid, packet_number, payload):
    """
    Constructs a representation of a QUIC short header using binary operations for the header fields.

    Parameters:
    - dcid: The Destination Connection ID as an integer.
    - packet_number: The packet number as an integer.
    - payload: The actual data payload as a string.

    Returns:
    A binary string representing the packet with a short header, followed by the payload in text.
    """

    # Header Form (0 for short header) and Key Phase Bit (assuming 0), both in binary
    # Note: In an actual implementation, these would be part of a single byte with other flags
    header_form = '0'  # 1 bit
    key_phase_bit = '0'  # 1 bit

    # Convert dcid and packet_number to binary strings
    # Here we assume dcid is represented with a fixed length for simplicity
    dcid_bin = format(dcid, '064b')  # Assuming 8 bytes for DCID, represented in 64 bits
    packet_number_bin = format(packet_number,
                               '032b')  # Assuming up to 4 bytes for packet number, represented in 32 bits

    # Constructing the short header in binary
    short_header_bin = header_form + key_phase_bit + dcid_bin + packet_number_bin

    # For simplicity, we concatenate the binary header and the string payload directly
    quic_packet_binary = short_header_bin + payload

    return quic_packet_binary


def parse_quic_short_header_binary(quic_packet_binary):
    """
    Parses a QUIC short header from a binary string representation, as constructed previously.

    Parameters:
    - quic_packet_binary: A binary string representing the packet with a short header, followed by a text payload.

    Returns:
    A dictionary with the parsed header components and payload.
    """

    # Extracting the binary components from the header
    header_form = quic_packet_binary[0]  # 1 bit
    key_phase_bit = quic_packet_binary[1]  # 1 bit

    # Assuming fixed lengths for DCID and Packet Number as in construction
    dcid_bin = quic_packet_binary[2:66]  # Next 64 bits for DCID
    packet_number_bin = quic_packet_binary[66:98]  # Next 32 bits for Packet Number

    # Convert binary components to their respective values
    dcid = int(dcid_bin, 2)
    packet_number = int(packet_number_bin, 2)

    # The remainder is the payload, still in string format
    payload = quic_packet_binary[98:]

    # Constructing and returning the parsed information
    parsed_header = {
        "header_form": int(header_form),
        "key_phase_bit": int(key_phase_bit),
        "dcid": dcid,
        "packet_number": packet_number,
        "payload": payload
    }

    return parsed_header


def construct_quic_frame(frame_type, stream_id, offset, data):
    """
    Constructs a simplified representation of a QUIC frame using binary operations.

    Parameters:
    - frame_type: An integer representing the frame type.
    - stream_id: An integer representing the stream identifier.
    - offset: An integer representing the data offset in this stream.
    - data: The actual data payload as a string.

    Returns:
    A binary string representing the frame.
    """

    # Convert frame type, stream ID, and offset to binary strings
    frame_type_bin = format(frame_type, '08b')  # Assuming 1 byte for frame type
    stream_id_bin = format(stream_id, '032b')  # Assuming 4 bytes for stream ID
    offset_bin = format(offset, '064b')  # Assuming 8 bytes for offset
    data_length_bin = format(len(data), '016b')  # Assuming 2 bytes for data length

    # Since we're keeping data as a string for simplicity, let's prepend it with its length in binary
    frame_binary = f"{frame_type_bin}{stream_id_bin}{offset_bin}{data_length_bin}{data}"
    return frame_binary


def parse_quic_frame(frame_binary):
    """
    Parses a simplified representation of a QUIC frame from a binary string.

    Parameters:
    - frame_binary: A binary string representing the frame.

    Returns:
    A dictionary with the parsed frame components.
    """

    # Extract binary components
    frame_type_bin = frame_binary[:8]  # 1 byte for frame type
    stream_id_bin = frame_binary[8:40]  # 4 bytes for stream ID
    offset_bin = frame_binary[40:104]  # 8 bytes for offset
    data_length_bin = frame_binary[104:120]  # 2 bytes for data length
    #print(frame_type_bin, stream_id_bin, offset_bin, data_length_bin)

    # Convert binary components to integers
    frame_type = int(frame_type_bin, 2)
    stream_id = int(stream_id_bin, 2)
    offset = int(offset_bin, 2)
    data_length = int(data_length_bin, 2)

    # Extract the data payload as a string
    # Note: In a real implementation, this would be handled as binary data
    data_start_index = 120  # Starting index of the data payload
    data_end_index = data_start_index + data_length * 8  # Assuming 8 bits per character in the string for simplicity
    data = frame_binary[data_start_index:data_end_index]

    # Construct and return the parsed frame information
    parsed_frame = {
        "frame_type": frame_type,
        "stream_id": stream_id,
        "offset": offset,
        "data_length": data_length,
        "data": data
    }

    return parsed_frame

def construct_quic_ack_packet(dcid, packet_number, ack_delay, ack_ranges):
    """
    Constructs a representation of a QUIC ack packets using binary operations for the header fields.

    Parameters:
    - dcid: The Destination Connection ID as an integer.
    - packet_number: The packet number as an integer.
    - ack_delay: (in ms) The maximum time a receiver might delay sending an ACK.
    - ack_ranges: A list of pairs that represent the ACKed ranges.

    Returns:
    A binary string representing the packet with an ACK packet.
    """

    # Header Form (1 for long header) and Key Phase Bit (assuming 0), both in binary
    # Note: In an actual implementation, these would be part of a single byte with other flags
    header_form = '1'  # 1 bit
    key_phase_bit = '0'  # 1 bit

    # Convert dcid and packet_number to binary strings
    # Here we assume dcid is represented with a fixed length for simplicity
    dcid_bin = format(dcid, '064b')  # Assuming 8 bytes for DCID, represented in 64 bits
    packet_number_bin = format(packet_number, '032b')  # Assuming up to 4 bytes for packet number, represented in 32 bits
    ack_delay_bin = format(ack_delay, '016b')  # Assuming up to 3 bytes for ACK delay in ms, represented in 16 bits
    blocks_count = format(len(ack_ranges), '032b') # Assuming up to 4 bytes for number of ACK ranges, represented in 32 bits

    # Constructing the header in binary
    quic_packet_binary = header_form + key_phase_bit + dcid_bin + packet_number_bin + ack_delay_bin + blocks_count

    # Constructing the ranges in binary
    for ack_range in ack_ranges:  # Assuming up to 4 bytes for packet number, represented in 32 bits
        quic_packet_binary += format(ack_range[0], '032b') + format(ack_range[1], '032b')

    return quic_packet_binary


def parse_quic_ack_packet(quic_packet_binary):
    """
    Parses a QUIC ACK packet from a binary string representation, as constructed previously.

    Parameters:
    - quic_packet_binary: A binary string representing the ACK packet.

    Returns:
    A dictionary with the parsed header components.
    """

    # Extracting the binary components from the header
    header_form = quic_packet_binary[0]  # 1 bit
    key_phase_bit = quic_packet_binary[1]  # 1 bit

    # Assuming fixed lengths for DCID and Packet Number as in construction
    dcid_bin = quic_packet_binary[2:66]  # Next 64 bits for DCID
    packet_number_bin = quic_packet_binary[66:98]  # Next 32 bits for Packet Number

    # Convert binary components to their respective values
    dcid = int(dcid_bin, 2)
    packet_number = int(packet_number_bin, 2)

    # Parse the ACK fields
    ack_delay = int(quic_packet_binary[98:114], 2)  # Next 16 bits are for ACK delay
    blocks_count = int(quic_packet_binary[114:146], 2)  # Next 32 bits are for blocks count
    ack_ranges = []
    i = 0
    while 210 + i*64 <= len(quic_packet_binary):
        left = int(quic_packet_binary[146 + i*64: 178 + i*64], 2)
        right = int(quic_packet_binary[178 + i*64: 210 + i*64], 2)
        ack_ranges.append((left,right))
        i += 1

    # Constructing and returning the parsed information
    parsed_header = {
        "header_form": int(header_form),
        "key_phase_bit": int(key_phase_bit),
        "dcid": dcid,
        "packet_number": packet_number,
        "ack_delay": ack_delay,
        "blocks_count": blocks_count,
        "ack_ranges": ack_ranges
    }

    return parsed_header

def send_hello_packet(socket, streamID, dcid, scid, side, address):
    """
    Sends an hello packet with a single frame.

    Parameters:
    - socket: The socket used for sending the packet.
    - streamID: The ID of the stream the packet is being sent on.
    - dcid: Destination CID as an integer.
    - scid: Source CID as an integer.
    - side: A string represnting the side of the connection: 'Server' or 'Client'.
    - address: (destination IP , destination port)
    """

    """
    ---Construct Hello frame---
    frame type 6 is being used for handshake
    offset is 0
    """
    hello_frame = construct_quic_frame(6, streamID, 0, side + "Hello")

    """
    ---Construct Hello packet---
    packet type is 0
    version is 1
    payload is hello_frame
    """
    hello_packet = construct_quic_long_header(0, 1, dcid, scid, hello_frame)
    socket.sendto(hello_packet.encode(), address)

def send_connection_close_packet(socket, streamID, dcid, packet_number, address):
    """
    Sends an connection_close packet with a single frame.

    Parameters:
    - socket: The socket used for sending the packet.
    - streamID: The ID of the stream the packet is being sent on.
    - dcid: Destination CID as an integer.
    - address: (destination IP , destination port)
    """

    """
    ---Construct CONNECTION_CLOSE frame---
    frame type 0x1c is being used for connection close
    offset is 0
    data is 'CONNECTION_CLOSE'
    """
    connection_close_frame = construct_quic_frame(0x1c, streamID, 0, "CONNECTION_CLOSE")


    # ---Construct CONNECTION_CLOSE packet---
    connection_close_packet = construct_quic_short_header_binary(dcid, packet_number, connection_close_frame)

    socket.sendto(connection_close_packet.encode(), address)


def time_based_recovery(sock, address, packet_queue, last_ack_time, current_packet_number, time_threshold):
    # Make a deep copy for packet_queue
    packet_queue_copy = copy.deepcopy(packet_queue)
    counter = 0
    for element in packet_queue_copy:
        if last_ack_time - element[2] > time_threshold and not element[1]:
            packet_queue.remove(element)

            # Assign the packet a new packet number and append it to the queue
            element[0] = current_packet_number
            lost_packet = parse_quic_short_header_binary(element[3])
            lost_packet['packet_number'] = current_packet_number
            element[3] = construct_quic_short_header_binary(lost_packet["dcid"], lost_packet["packet_number"],
                                                                lost_packet["payload"])
            element[2] = datetime.timestamp(datetime.now())
            packet_queue.append(element)

            # Resend the packet
            sock.sendto(element[3].encode(), address)
            counter += 1
            current_packet_number += 1
    return counter, current_packet_number


def packet_number_based_recovery(sock, address, packet_queue,current_packet_number, packet_reoredering_threshold):
    last_ack = 0
    i = 0

    for element in reversed(packet_queue):
        if element[1]:
            last_ack = len(packet_queue) - i - 1
            break
        i += 1

    
    counter = 0
    for i in range(0, last_ack - packet_reoredering_threshold):
        if packet_queue[0][1]:
            packet_queue.popleft()
        else:
            # Update the lost packet in the queue
            packet_queue[0][0] = current_packet_number
            lost_packet = parse_quic_short_header_binary(packet_queue[0][3])
            lost_packet['packet_number'] = current_packet_number
            packet_queue[0][3] = construct_quic_short_header_binary(lost_packet["dcid"],
                                                                        lost_packet["packet_number"],
                                                                        lost_packet["payload"])
            packet_queue[0][2] = datetime.timestamp(datetime.now())

            # Append it to the queue and send it again
            packet_queue.append(packet_queue[0])
            sock.sendto(packet_queue[0][3].encode(), address)

            counter += 1
            current_packet_number += 1
            packet_queue.popleft()
    return counter, current_packet_number


def PTO_recovery(sock, address, packet_queue, current_packet_number, PTO_TIMEOUT):
    
    # Make a deep copy for packet_queue
    packet_queue_copy = copy.deepcopy(packet_queue)
    counter = 0
    for element in packet_queue_copy:
        if datetime.now().timestamp() - element[2] > PTO_TIMEOUT and not element[1]:
            packet_queue.remove(element)

            element[0] = current_packet_number
            lost_packet = parse_quic_short_header_binary(element[3])
            lost_packet['packet_number'] = current_packet_number
            element[3] = construct_quic_short_header_binary(lost_packet["dcid"], lost_packet["packet_number"],
                                                                lost_packet["payload"])
            element[2] = datetime.timestamp(datetime.now())

            packet_queue.append(element)
            sock.sendto(element[3].encode(), address)
            counter += 1
            current_packet_number += 1
    return counter, current_packet_number


def receive_ACKs(sock, address, packet_queue, tail, current_packet_number, TIME_THRESHOLD, PACKET_REORDERING_THRESHOLD, PTO_TIMEOUT):
    time_retransmit_counter = 0
    packet_number_retransmit_counter = 0
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

                # Avoid parsing short headers
                if ack[0] == ord('0'):
                    continue

                ack_packet = parse_quic_ack_packet(ack)
                ack_ranges = ack_packet['ack_ranges']
                curr_block = 0
                for element in packet_queue:
                    if curr_block >= len(ack_ranges):
                        break
                    if ack_ranges[curr_block][0] <= element[0] <= ack_ranges[curr_block][1]:
                        element[1] = True
                    elif element[0] > ack_ranges[curr_block][1]:
                        curr_block += 1

            else:
                # No more ACKs available, break from the loop
                break

    except BlockingIOError:
        # No data available
        pass

    # Pop all True elements from the head of the deque until reaching false
    while packet_queue and packet_queue[0][1]:
        packet_queue.popleft()

    if TIME_THRESHOLD:
        count, packet_number = time_based_recovery(sock,address,packet_queue, last_ack_time,current_packet_number, TIME_THRESHOLD)
        retransmit_counter += count
        time_retransmit_counter += count
        current_packet_number = packet_number

    if PACKET_REORDERING_THRESHOLD:
        count, packet_number = packet_number_based_recovery(sock,address,packet_queue,current_packet_number, PACKET_REORDERING_THRESHOLD)
        retransmit_counter += count
        packet_number_retransmit_counter += count
        current_packet_number = packet_number

    if tail:  # PTO for tail packets
        count, packet_number = PTO_recovery(sock,address,packet_queue,current_packet_number,PTO_TIMEOUT)
        retransmit_counter += count
        current_packet_number = packet_number

    return retransmit_counter,  time_retransmit_counter, packet_number_retransmit_counter, current_packet_number