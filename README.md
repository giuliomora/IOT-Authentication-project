

# IoT Authentication Project

This repository contains a mutual authentication protocol for IoT devices using a shared cryptographic vault and session-based key updates. The codebase includes protocol logic, vault management, and scripts for initialization and testing.

## Directory Structure

```
Autentication/
  client.py            # Device-side protocol logic
  server.py            # Server-side protocol logic
  vault.py             # Vault management functions
  initialize_vault.py  # Vault setup script
  utils.py             # Cryptographic utilities
  constants.py         # Configuration constants
  experiments.py       # Brute-force simulation
```

## Protocol Steps

1. The client sends device and session information to the server.
2. The server generates a challenge and sends it to the client.
3. The client computes a session key, generates random values, and sends an encrypted response.
4. The server decrypts the response, checks the challenge, generates new random values, and sends an encrypted reply.
5. Both client and server update their vaults using exchanged data.

## File Descriptions

- `client.py`: Runs the device protocol. Connects to the server, loads the vault, performs authentication, and updates the vault. Main function: `run_device_protocol()`.
- `server.py`: Runs the server protocol. Waits for a client, loads the vault, handles authentication, updates and saves the vault. Main function: `run_server_protocol()`.
- `vault.py`: Functions for vault initialization, loading, saving, and updating.
- `initialize_vault.py`: Script to create a new vault. Usage:
  ```bash
  python3 initialize_vault.py --key-size 16
  python3 initialize_vault.py --key-size 32
  ```
- `utils.py`: Cryptographic functions (AES encryption/decryption, padding, random index generation, XOR key derivation).
- `constants.py`: Configuration values (vault size, key sizes, server host/port).
- `experiments.py`: Brute-force simulation on the vault. Attempts to guess the vault or its keys and reports attempts and time. Main functions: `simulate_brute_force`, `simulate_keywise_brute_force`.

## How to Run

1. Initialize the vault:
   ```bash
   python3 initialize_vault.py --key-size 16
   ```
2. Start the server:
   ```bash
   python3 server.py
   ```
3. Run the client (in a separate terminal):
   ```bash
   python3 client.py
   ```
4. Run experiments (optional):
   ```bash
   python3 experiments.py
   ```
