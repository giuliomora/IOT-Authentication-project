import os
import time
import itertools
from constants import AES_KEY_SIZE
from vault import load_vault

def make_random_vault(length, keylen):
    """Create a vault with random keys."""
    return [os.urandom(keylen) for _ in range(length)]

def simulate_brute_force(vault_ref, keylen, vaultlen):
    print("Brute force vault simulation started.")
    tries = 0
    t0 = time.time()
    while True:
        tries += 1
        guess = make_random_vault(vaultlen, keylen)
        if guess == vault_ref:
            break
        if tries % 100000 == 0:
            print(f"Tries: {tries} ... still running")
    t1 = time.time() - t0
    return tries, t1

def simulate_keywise_brute_force(vault_ref, keylen):
    print("Key-by-key brute force simulation started.")
    tries = 0
    t0 = time.time()
    found_keys = []
    for idx, ref_key in enumerate(vault_ref):
        print(f"Trying to guess key {idx+1}/{len(vault_ref)}")
        found = False
        for candidate in itertools.product(range(256), repeat=keylen):
            tries += 1
            if bytes(candidate) == ref_key:
                print(f"Key {idx+1} found after {tries} tries.")
                found_keys.append(bytes(candidate))
                found = True
                break
        if not found:
            print(f"Key {idx+1} not found (unexpected)")
            break
    t1 = time.time() - t0
    return tries, t1

if __name__ == "__main__":
    vault = load_vault()
    attempts, elapsed = simulate_keywise_brute_force(vault, AES_KEY_SIZE)
    print("Brute force completed.")
    print(f"Total attempts: {attempts}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
