
import random
import socket
import pickle
from constants import SERVER_HOST, SERVER_PORT
from vault import load_vault, update_vault
from utils import decrypt, encrypt, generate_random_indices, pad_data, unpad_data, xor_keys

def run_device_protocol():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))

        session_count = 5
        vault_data, vault_key_size = load_vault()
        print(f"Vault key size: {vault_key_size} bytes")

        for sid in range(session_count):
            print(f"\n[Session {sid}] Start")

            # Step 1: Send device and session info
            dev_id = "Device123"
            msg1 = pickle.dumps((dev_id, sid))
            sock.sendall(msg1)
            print(f"Sent: Device={dev_id}, Session={sid}")

            # Step 2: Receive challenge
            challenge_data = sock.recv(1024)
            indices_1, rand_1 = pickle.loads(challenge_data)
            print(f"Received challenge: Indices={indices_1}, Nonce={rand_1.hex()}")

            # Step 3: Prepare and send response
            key_1 = xor_keys(vault_data, indices_1)
            nonce_1 = random.getrandbits(vault_key_size*8).to_bytes(vault_key_size, 'big')
            indices_2 = generate_random_indices(len(vault_data))
            nonce_2 = random.getrandbits(vault_key_size*8).to_bytes(vault_key_size, 'big')
            payload = pickle.dumps((rand_1, nonce_1, indices_2, nonce_2))
            enc_payload = encrypt(key_1, pad_data(payload, vault_key_size))
            sock.sendall(enc_payload)
            print(f"Sent response: Nonce1={rand_1.hex()}, Temp={nonce_1.hex()}, Indices2={indices_2}, Nonce2={nonce_2.hex()}")

            # Step 4: Receive and process server reply
            reply = sock.recv(1024)
            key_2 = xor_keys(vault_data, indices_2)
            combined_key = int.from_bytes(key_2, 'big') ^ int.from_bytes(nonce_1, 'big')
            combined_key = combined_key.to_bytes(len(key_2), 'big')
            dec_reply = unpad_data(decrypt(combined_key, reply), vault_key_size)
            nonce2_check, temp2 = pickle.loads(dec_reply)
            print(f"Received reply: Nonce2={nonce2_check.hex()}, Temp2={temp2.hex()}")

            # Step 5: Check and update vault
            if nonce_2 != nonce2_check:
                print("Auth error: Nonce2 mismatch")
                continue
            new_material = (int.from_bytes(key_1, 'big') ^ int.from_bytes(key_2, 'big')).to_bytes(len(key_1), 'big')
            vault_data = update_vault(vault_data, new_material, vault_key_size)
            print(f"[Session {sid}] Vault updated")

if __name__ == "__main__":
    run_device_protocol()
