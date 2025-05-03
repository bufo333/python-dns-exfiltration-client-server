from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Generate private key
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()

# Save private key (raw 32 bytes)
with open("server.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key (raw 32 bytes)
with open("server_public.key", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

# Append to .env
with open(".env", "a") as f:
    f.write("SERVER_PUBLIC_KEY=server_public.key\n")
