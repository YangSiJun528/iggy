#!/usr/bin/env python3
"""
IGGY Protocol Test Message Generator

This script generates test IGGY protocol messages for testing the Wireshark dissector.
It does NOT connect to a real IGGY server - it just creates binary protocol messages
that can be captured and analyzed.

Usage:
    python test_protocol.py

This will create sample messages and print them in hex format.
To capture these messages, you can use scapy or write them to a file.
"""

import struct
import sys

# Little Endian encoding throughout


def u8(value):
    """Encode u8"""
    return struct.pack('<B', value)


def u32(value):
    """Encode u32 little endian"""
    return struct.pack('<I', value)


def u64(value):
    """Encode u64 little endian"""
    return struct.pack('<Q', value)


def string_u8(s):
    """Encode string with u8 length prefix"""
    s_bytes = s.encode('utf-8')
    return u8(len(s_bytes)) + s_bytes


def string_u32(s):
    """Encode string with u32 length prefix"""
    if s is None or len(s) == 0:
        return u32(0)
    s_bytes = s.encode('utf-8')
    return u32(len(s_bytes)) + s_bytes


def identifier_numeric(id_val):
    """Encode numeric identifier"""
    return u8(1) + u8(4) + u32(id_val)


def identifier_string(id_str):
    """Encode string identifier"""
    s_bytes = id_str.encode('utf-8')
    return u8(2) + u8(len(s_bytes)) + s_bytes


def partitioning_balanced():
    """Encode balanced partitioning"""
    return u8(1) + u8(0)


def partitioning_partition_id(partition_id):
    """Encode partition ID partitioning"""
    return u8(2) + u8(4) + u32(partition_id)


def build_request(command_code, payload):
    """Build IGGY request message"""
    length = len(payload) + 4  # +4 for command code
    return u32(length) + u32(command_code) + payload


def build_response(status, payload):
    """Build IGGY response message"""
    return u32(status) + u32(len(payload)) + payload


# Test message builders

def test_ping():
    """PING (1) - No payload"""
    return build_request(1, b'')


def test_login_user():
    """LOGIN_USER (38)"""
    payload = (
        string_u8("testuser") +
        string_u8("testpass123") +
        string_u32("dissector-test-v1.0") +
        string_u32("wireshark-testing")
    )
    return build_request(38, payload)


def test_logout_user():
    """LOGOUT_USER (39) - No payload"""
    return build_request(39, b'')


def test_create_stream():
    """CREATE_STREAM (202)"""
    payload = (
        u32(0) +  # Stream ID (0 = auto-assign)
        string_u8("test_stream")
    )
    return build_request(202, payload)


def test_get_stream():
    """GET_STREAM (200)"""
    payload = identifier_numeric(1)
    return build_request(200, payload)


def test_get_streams():
    """GET_STREAMS (201) - No payload"""
    return build_request(201, b'')


def test_delete_stream():
    """DELETE_STREAM (203)"""
    payload = identifier_string("test_stream")
    return build_request(203, payload)


def test_create_topic():
    """CREATE_TOPIC (302)"""
    payload = (
        identifier_numeric(1) +  # Stream ID
        u32(0) +  # Topic ID (0 = auto-assign)
        u32(3) +  # Partitions count
        string_u8("test_topic") +
        u32(0)  # Message expiry (0 = never)
    )
    return build_request(302, payload)


def test_get_topic():
    """GET_TOPIC (300)"""
    payload = (
        identifier_numeric(1) +  # Stream ID
        identifier_numeric(1)   # Topic ID
    )
    return build_request(300, payload)


def test_poll_messages():
    """POLL_MESSAGES (100)"""
    payload = (
        u8(1) +  # Consumer kind (1 = Consumer)
        identifier_string("test_consumer") +
        identifier_numeric(1) +  # Stream ID
        identifier_numeric(1) +  # Topic ID
        u32(1) +  # Partition ID
        u8(3) +   # Strategy kind (3 = First)
        u64(0) +  # Strategy value
        u32(10) +  # Count (10 messages)
        u8(1)     # Auto commit (true)
    )
    return build_request(100, payload)


def test_send_messages():
    """SEND_MESSAGES (101) - Simplified version"""
    # For simplicity, we'll create a message with minimal data
    stream_id = identifier_numeric(1)
    topic_id = identifier_numeric(1)
    partitioning = partitioning_balanced()
    msg_count = u32(1)

    # Calculate metadata length
    metadata = stream_id + topic_id + partitioning + msg_count
    metadata_length = u32(len(metadata))

    # Index table (16 bytes per message)
    # Reserved(8) + CumulativeSize(4) + Reserved(4)
    index_entry = b'\x00' * 8 + u32(100) + b'\x00' * 4

    # Messages data (dummy 100 bytes)
    messages_data = b'X' * 100

    payload = metadata_length + metadata + index_entry + messages_data
    return build_request(101, payload)


def test_store_consumer_offset():
    """STORE_CONSUMER_OFFSET (121)"""
    payload = (
        u8(1) +  # Consumer kind
        identifier_string("test_consumer") +
        identifier_numeric(1) +  # Stream ID
        identifier_numeric(1) +  # Topic ID
        u32(1) +  # Partition ID
        u64(12345)  # Offset
    )
    return build_request(121, payload)


def test_get_consumer_offset():
    """GET_CONSUMER_OFFSET (120)"""
    payload = (
        u8(1) +  # Consumer kind
        identifier_string("test_consumer") +
        identifier_numeric(1) +  # Stream ID
        identifier_numeric(1) +  # Topic ID
        u32(1)   # Partition ID
    )
    return build_request(120, payload)


def test_create_consumer_group():
    """CREATE_CONSUMER_GROUP (602)"""
    payload = (
        identifier_numeric(1) +  # Stream ID
        identifier_numeric(1) +  # Topic ID
        u32(1) +  # Consumer Group ID
        string_u8("test_group")
    )
    return build_request(602, payload)


def test_get_consumer_group():
    """GET_CONSUMER_GROUP (600)"""
    payload = (
        identifier_numeric(1) +  # Stream ID
        identifier_numeric(1) +  # Topic ID
        identifier_numeric(1)   # Consumer Group ID
    )
    return build_request(600, payload)


def test_success_response():
    """Success response (empty payload)"""
    return build_response(0, b'')


def test_error_response():
    """Error response"""
    return build_response(100, b'')  # Error code 100


def print_hex(data, label):
    """Print binary data as hex"""
    hex_str = ' '.join(f'{b:02x}' for b in data)
    print(f"\n{label}:")
    print(f"  Length: {len(data)} bytes")
    print(f"  Hex: {hex_str}")
    return data


def main():
    """Generate test messages"""
    print("=" * 80)
    print("IGGY Protocol Test Messages Generator")
    print("=" * 80)

    messages = [
        ("PING", test_ping()),
        ("LOGIN_USER", test_login_user()),
        ("LOGOUT_USER", test_logout_user()),
        ("CREATE_STREAM", test_create_stream()),
        ("GET_STREAM", test_get_stream()),
        ("GET_STREAMS", test_get_streams()),
        ("DELETE_STREAM", test_delete_stream()),
        ("CREATE_TOPIC", test_create_topic()),
        ("GET_TOPIC", test_get_topic()),
        ("POLL_MESSAGES", test_poll_messages()),
        ("SEND_MESSAGES", test_send_messages()),
        ("STORE_CONSUMER_OFFSET", test_store_consumer_offset()),
        ("GET_CONSUMER_OFFSET", test_get_consumer_offset()),
        ("CREATE_CONSUMER_GROUP", test_create_consumer_group()),
        ("GET_CONSUMER_GROUP", test_get_consumer_group()),
        ("Success Response", test_success_response()),
        ("Error Response", test_error_response()),
    ]

    all_data = b''
    for label, data in messages:
        print_hex(data, label)
        all_data += data

    # Write to binary file
    output_file = "test_messages.bin"
    with open(output_file, 'wb') as f:
        f.write(all_data)

    print("\n" + "=" * 80)
    print(f"All messages written to: {output_file}")
    print(f"Total size: {len(all_data)} bytes")
    print("\nTo capture with tcpdump:")
    print("  tcpdump -i lo -w iggy_test.pcap 'tcp port 8090'")
    print("\nTo use with IGGY SDK:")
    print("  1. Start IGGY server")
    print("  2. Run IGGY client commands")
    print("  3. Capture traffic with tcpdump")
    print("  4. Open pcap in Wireshark")
    print("=" * 80)


if __name__ == "__main__":
    main()
