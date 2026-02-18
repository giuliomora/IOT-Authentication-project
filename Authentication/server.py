
import random
import socket
import pickle
from constants import SERVER_HOST, SERVER_PORT
from vault import load_vault, update_vault
from utils import decrypt, encrypt, generate_random_indices, pad_data, unpad_data, xor_keys

def run_server_protocol():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_sock:
        srv_sock.bind((SERVER_HOST, SERVER_PORT))
        srv_sock.listen(1)
        print(f"Listening on port {SERVER_PORT}")

        conn, addr = srv_sock.accept()
        with conn:
            print(f"Connection from {addr}")

            session_total = 5
            vault_data, vault_key_size = load_vault()
            print(f"Vault key size: {vault_key_size} bytes")

            for sid in range(session_total):
                print(f"\n[Session {sid}] Start")

                # Step 1: Receive device/session info
                msg1 = conn.recv(1024)
                dev_id, sess_id = pickle.loads(msg1)
                print(f"Received: Device={dev_id}, Session={sess_id}")

                # Step 2: Send challenge
                indices_1 = generate_random_indices(len(vault_data))
                rand_1 = random.getrandbits(vault_key_size*8).to_bytes(vault_key_size, 'big')
                conn.sendall(pickle.dumps((indices_1, rand_1)))
                print(f"Sent challenge: Indices={indices_1}, Nonce={rand_1.hex()}")

                # Step 3: Receive and process response
                enc_payload = conn.recv(1024)
                key_1 = xor_keys(vault_data, indices_1)
                dec_payload = unpad_data(decrypt(key_1, enc_payload), vault_key_size)
                nonce1_check, temp1, indices_2, nonce_2 = pickle.loads(dec_payload)
                print(f"Received response: Nonce1={nonce1_check.hex()}, Temp1={temp1.hex()}, Indices2={indices_2}, Nonce2={nonce_2.hex()}")

                # Step 4: Check nonce and reply
                if rand_1 != nonce1_check:
                    print("Auth error: Nonce1 mismatch")
                    continue
                temp2 = random.getrandbits(vault_key_size*8).to_bytes(vault_key_size, 'big')
                key_2 = xor_keys(vault_data, indices_2)
                combined_key = int.from_bytes(key_2, 'big') ^ int.from_bytes(temp1, 'big')
                combined_key = combined_key.to_bytes(len(key_2), 'big')
                reply = pickle.dumps((nonce_2, temp2))
                enc_reply = encrypt(combined_key, pad_data(reply, vault_key_size))
                conn.sendall(enc_reply)
                print(f"Sent reply: Nonce2={nonce_2.hex()}, Temp2={temp2.hex()}")

                # Step 5: Update vault
                new_material = (int.from_bytes(key_1, 'big') ^ int.from_bytes(key_2, 'big')).to_bytes(len(key_1), 'big')
                vault_data = update_vault(vault_data, new_material, vault_key_size)
                from vault import save_vault
                save_vault(vault_data, vault_key_size)
                print(f"[Session {sid}] Vault updated and saved")

if __name__ == "__main__":
    run_server_protocol()
