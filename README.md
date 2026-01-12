# Project for SEC537 Course - Sabanci University

## Use Guide

1. Build and start the environment using Docker Compose:

    docker-compose up --build

2. Access the SCADA web application from your browser:

    http://localhost:5000

---
## sabanci is the vulnerable version of the system

## sabanci_sicuro is the patched version

---
# List of User

| ID | Username  | Ruolo        | Password        |
|----|-----------|--------------|-----------------|
| 1  | Mario     | normal       | password123    |
| 2  | Luigi     | normal       | maint2024      |
| 3  | Giorgio   | normal       | wrench!        |
| 4  | superman  | technician   | supervisor123  |
| 5  | admin     | technician   | forzatoro      |

---

## File Description

The following files are included to support the demonstration of specific vulnerabilities.

### encrypter.py

This script is used to demonstrate **Vulnerability 2.4 – File Scanning Pipeline Bypass via Encryption**.

- A malicious Python payload is generated.
- The payload is encrypted using a weak XOR-based scheme with a static key.
- The encrypted output (`malware.bin`) bypasses the simulated antivirus, which only scans plaintext.
- Once decrypted server-side, the payload is executed, resulting in arbitrary command execution.

This demonstrates how encrypted content can evade insufficient security controls.

---

### exploit.py

This script demonstrates **Vulnerability 2.3 – Unrestricted File Upload Leading to Remote Code Execution (RCE)**.

- The script establishes a reverse shell to an attacker-controlled host.
- Standard input, output, and error streams are redirected to a TCP socket.
- Once executed, the attacker gains an interactive shell on the target system.

A listening service (e.g., Netcat) must be active on the attacker machine before execution.

---

### mySecret.txt

This file contains sensitive information:

    This is my secret.

- The file is unintentionally exposed due to **Vulnerability 2.5 – File Path Injection / Directory Traversal**.
- It demonstrates how improper path validation allows attackers to access confidential files.


---


