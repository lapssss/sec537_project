#Script
payload = """
import os
import subprocess
print("--- BYPASS COMPLETED ---")
print(subprocess.check_output(['ls', '-la', '/']).decode())
"""

key = "secret123"

# XOR Encryption
encrypted = bytes([b ^ key.encode()[i % len(key)] for i, b in enumerate(payload.encode())])

with open("malware.bin", "wb") as f:
    f.write(encrypted)