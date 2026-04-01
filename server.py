import socket
import threading
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


class SecureServer:
    def __init__(self, host=HOST, control_port=CONTROL_PORT):
        self.host = host
        self.control_port = control_port

        self.private_key = None
        self.public_key = None

        self.control_socket = None

        # Store client public key by data port
        self.client_public_keys = {}

    def start(self):
        print("Starting server...")
        print("Creating RSA keypair")
        self.private_key, self.public_key = generate_rsa_keypair()
        print("RSA keypair created")

        print("Creating server socket")
        self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.control_socket.bind((self.host, self.control_port))
        self.control_socket.listen(5)

        print("Awaiting connections...")

        while True:
            client_sock, client_addr = self.control_socket.accept()
            threading.Thread(
                target=self.handle_control_connection,
                args=(client_sock, client_addr),
                daemon=True
            ).start()

    def handle_control_connection(self, client_sock, client_addr):
        try:
            request = client_sock.recv(BUFFER_SIZE).decode().strip().lower()

            if request == "connect":
                print("Connection requested. Creating data socket")

                data_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_listener.bind((self.host, 0))
                data_listener.listen(1)

                data_port = data_listener.getsockname()[1]
                client_sock.sendall(str(data_port).encode())

                data_sock, data_addr = data_listener.accept()
                self.handle_data_connection(data_sock, data_addr, data_port)

                data_listener.close()
            else:
                client_sock.sendall(b"INVALID_COMMAND")

        except Exception as e:
            print(f"[SERVER CONTROL ERROR] {e}")
        finally:
            client_sock.close()

    def handle_data_connection(self, data_sock, data_addr, data_port):
        try:
            while True:
                raw_data = data_sock.recv(BUFFER_SIZE)
                if not raw_data:
                    break

                try:
                    packet = json.loads(raw_data.decode())
                except Exception:
                    data_sock.sendall(json.dumps({"error": "INVALID_PACKET"}).encode())
                    continue

                command = packet.get("command", "").lower()

                if command == "tunnel":
                    print("Tunnel requested. Sending public key")

                    client_key_data = packet.get("client_public_key")
                    client_public_key = deserialize_public_key(client_key_data)
                    self.client_public_keys[data_port] = client_public_key

                    response = {
                        "server_public_key": serialize_public_key(self.public_key)
                    }
                    data_sock.sendall(json.dumps(response).encode())

                elif command == "post":
                    print("Post requested.")

                    encrypted_message = packet.get("message", "")
                    print(f"Received encrypted message: {encrypted_message}")

                    decrypted_message = decrypt_message(
                        encrypted_message.encode(),
                        self.private_key
                    )
                    print(f"Decrypted message: {decrypted_message}")

                    print("Computing hash")
                    message_hash = compute_sha256(decrypted_message)

                    client_public_key = self.client_public_keys.get(data_port)
                    encrypted_hash = encrypt_message(message_hash, client_public_key)

                    print(f"Responding with hash: {message_hash}")

                    response = {
                        "encrypted_hash": encrypted_hash.decode(errors="ignore")
                        if isinstance(encrypted_hash, bytes)
                        else str(encrypted_hash)
                    }
                    data_sock.sendall(json.dumps(response).encode())

                else:
                    data_sock.sendall(json.dumps({"error": "INVALID_COMMAND"}).encode())

        except Exception as e:
            print(f"[SERVER DATA ERROR] {e}")
        finally:
            data_sock.close()


if __name__ == "__main__":
    server = SecureServer()
    server.start()