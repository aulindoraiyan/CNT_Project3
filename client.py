import socket
import json

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    encrypt_message,
    decrypt_message,
    compute_sha256,
)

HOST = "127.0.0.1"
CONTROL_PORT = 8080
BUFFER_SIZE = 4096


class SecureClient:
    def __init__(self, host=HOST, control_port=CONTROL_PORT):
        self.host = host
        self.control_port = control_port

        self.private_key = None
        self.public_key = None
        self.server_public_key = None

    def run(self, message="Hello"):
        control_sock = None
        data_sock = None

        try:
            print("Starting client...")
            print("Creating RSA keypair")
            self.private_key, self.public_key = generate_rsa_keypair()
            print("RSA keypair created")

            print("Creating client socket")
            control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            print("Connecting to server")
            control_sock.connect((self.host, self.control_port))
            control_sock.sendall(b"connect")

            data_port_response = control_sock.recv(BUFFER_SIZE).decode().strip()
            if not data_port_response.isdigit():
                raise ValueError(f"Invalid data port received from server: {data_port_response}")

            data_port = int(data_port_response)
            control_sock.close()
            control_sock = None

            print("Creating data socket")
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.connect((self.host, data_port))

            print("Requesting tunnel")
            tunnel_packet = {
                "command": "tunnel",
                "client_public_key": serialize_public_key(self.public_key)
            }
            data_sock.sendall(json.dumps(tunnel_packet).encode())

            tunnel_response_raw = data_sock.recv(BUFFER_SIZE).decode()
            tunnel_response = json.loads(tunnel_response_raw)

            if "server_public_key" not in tunnel_response:
                raise ValueError("Server did not return a public key during tunnel phase.")

            self.server_public_key = deserialize_public_key(
                tunnel_response["server_public_key"]
            )

            print("Server public key received")
            print("Tunnel established")

            print(f"Encrypting message: {message}")
            encrypted_message = encrypt_message(message, self.server_public_key)

            encrypted_display = (
                encrypted_message.decode(errors="ignore")
                if isinstance(encrypted_message, bytes)
                else str(encrypted_message)
            )

            print(f"Sending encrypted message: {encrypted_display}")

            post_packet = {
                "command": "post",
                "message": encrypted_display
            }
            data_sock.sendall(json.dumps(post_packet).encode())

            response_raw = data_sock.recv(BUFFER_SIZE).decode()
            response = json.loads(response_raw)

            if "encrypted_hash" not in response:
                raise ValueError("Server response does not contain 'encrypted_hash'.")

            encrypted_hash = response["encrypted_hash"]

            print("Received hash")
            server_hash = decrypt_message(encrypted_hash.encode(), self.private_key)

            print("Computing hash")
            local_hash = compute_sha256(message)

            if local_hash == server_hash:
                print("Secure")
            else:
                print("Compromised")

        except Exception as e:
            print(f"[CLIENT ERROR] {e}")

        finally:
            if control_sock:
                control_sock.close()
            if data_sock:
                data_sock.close()


if __name__ == "__main__":
    client = SecureClient()
    client.run()