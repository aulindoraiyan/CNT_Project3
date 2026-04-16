import socket
import threading
import json
import base64

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
                daemon=True,
            ).start()

    def handle_control_connection(self, client_sock, client_addr):
        """
        Handle the initial control connection.
        The only valid command on the control socket is 'connect'.
        On connect, a new data socket is created on a dynamic port
        and the port number is sent back to the client.
        """
        try:
            request = client_sock.recv(BUFFER_SIZE).decode().strip().lower()

            if request == "connect":
                print("Connection requested. Creating data socket")

                # Create a temporary listener on a random available port
                data_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_listener.bind((self.host, 0))
                data_listener.listen(1)

                data_port = data_listener.getsockname()[1]

                # Send the data port back to the client on the control socket
                client_sock.sendall(str(data_port).encode())

                # Wait for the client to connect on the data port
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
        """
        Handle commands on the data socket (tunnel, post).
        Runs in a loop so the client can send multiple commands
        on the same data connection.
        """
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
                    self._handle_tunnel(packet, data_sock, data_port)

                elif command == "post":
                    self._handle_post(packet, data_sock, data_port)

                else:
                    data_sock.sendall(
                        json.dumps({"error": "INVALID_COMMAND"}).encode()
                    )

        except Exception as e:
            print(f"[SERVER DATA ERROR] {e}")
        finally:
            data_sock.close()

    def _handle_tunnel(self, packet, data_sock, data_port):
        """
        tunnel command:
        - Receive and store the client's public key
        - Respond with the server's public key
        """
        print("Tunnel requested. Sending public key")

        client_key_data = packet.get("client_public_key")
        client_public_key = deserialize_public_key(client_key_data)
        self.client_public_keys[data_port] = client_public_key

        response = {"server_public_key": serialize_public_key(self.public_key)}
        data_sock.sendall(json.dumps(response).encode())

    def _handle_post(self, packet, data_sock, data_port):
        """
        post command:
        - Receive the encrypted message (base64-encoded)
        - Decrypt it using the server's private key
        - Compute SHA256 hash of the plaintext
        - Encrypt the hash using the client's public key
        - Respond with the encrypted hash (base64-encoded)
        """
        print("Post requested.")

        encrypted_b64 = packet.get("message", "")
        print(f"Received encrypted message: {encrypted_b64}")

        # Decode from base64 back to raw bytes, then decrypt
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
        except Exception:
            # Fallback: treat the message as raw encoded string
            encrypted_bytes = encrypted_b64.encode()

        decrypted_message = decrypt_message(encrypted_bytes, self.private_key)
        print(f"Decrypted message: {decrypted_message}")

        print("Computing hash")
        message_hash = compute_sha256(decrypted_message)

        # Encrypt the hash using the client's public key
        client_public_key = self.client_public_keys.get(data_port)
        encrypted_hash = encrypt_message(message_hash, client_public_key)

        # Base64-encode the encrypted hash so it survives JSON transport
        if isinstance(encrypted_hash, bytes):
            encrypted_hash_b64 = base64.b64encode(encrypted_hash).decode()
        else:
            encrypted_hash_b64 = str(encrypted_hash)

        print(f"Responding with hash: {message_hash}")

        response = {"encrypted_hash": encrypted_hash_b64}
        data_sock.sendall(json.dumps(response).encode())


if __name__ == "__main__":
    server = SecureServer()
    server.start()
