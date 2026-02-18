
import os
import time
import itertools
from constants import AES_KEY_SIZE
from vault import load_vault

def generate_vault(num_keys, key_size):
    """Generate a vault with random keys."""
    return [os.urandom(key_size) for _ in range(num_keys)]

def brute_force_entire_vault(target_vault, key_size, vault_size):
    print("[INFO] Starting full vault brute force...")
    attempt_count = 0
    start = time.time()
    while True:
        attempt_count += 1
        candidate = generate_vault(vault_size, key_size)
        if candidate == target_vault:
            break
        if attempt_count % 100000 == 0:
            print(f"[INFO] Attempts: {attempt_count} ... still running")
    elapsed = time.time() - start
    return attempt_count, elapsed

def brute_force_each_key(target_vault, key_size):
    print("[INFO] Starting key-by-key brute force...")
    attempt_count = 0
    start = time.time()
    recovered_keys = []
    for key_idx, real_key in enumerate(target_vault):
        print(f"[INFO] Guessing key {key_idx+1}/{len(target_vault)}")
        found = False
        for guess_tuple in itertools.product(range(256), repeat=key_size):
            attempt_count += 1
            guess_bytes = bytes(guess_tuple)
            if guess_bytes == real_key:
                print(f"[INFO] Key {key_idx+1} found after {attempt_count} attempts.")
                recovered_keys.append(guess_bytes)
                found = True
                break
        if not found:
            print(f"[WARN] Key {key_idx+1} not found (unexpected)")
            break
    elapsed = time.time() - start
    return attempt_count, elapsed

if __name__ == "__main__":
    vault_data = load_vault()
    attempts, duration = brute_force_each_key(vault_data, AES_KEY_SIZE)
    print("[RESULT] Brute force completed.")
    print(f"[RESULT] Total attempts: {attempts}")
    print(f"[RESULT] Elapsed time: {duration:.2f} seconds")
