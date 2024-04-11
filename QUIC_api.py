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
    ---Construct ClientHello frame---
    frame type 6 is being used for handshake
    offset is 0
    """
    hello_frame = construct_quic_frame(6, streamID, 0, side + "Hello")

    """
    ---Construct ClientHello packet---
    packet type is 0
    version is 1
    payload is client_hello_frame
    """
    hello_packet = construct_quic_long_header(0, 1, dcid, scid, hello_frame)
    socket.sendto(hello_packet.encode(), address)

def send_connection_close_packet(socket, streamID, dcid, packet_number, address):
    """
    Sends an hello packet with a single frame.

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