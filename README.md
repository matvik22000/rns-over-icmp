# rns-over-icmp

This small script allows using ICMP PING packets as a transport layer for Reticulum.
It consists of two parts: a client and a server. The **server** must have a public IP address (or any other way for the client to ping it). The **client** only needs a computer.
One server can serve **any number** of clients.

## Setup

1. Install dependencies:

   ```bash
   pip install scapy
   ```

2. Grant Python access to low-level sockets:

   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip /path/to/your/bin/python
   ```

   Notes:
   - venv pythons are usually symlinks to the system interpreter; resolve the
     real binary with `readlink -f .venv/bin/python3` and set the caps on that.
   - The caps are lost when the interpreter binary is replaced (e.g. a system
     update replaces /usr/bin/python3.12) — the tunnel will exit with a clear
     "no permission for raw sockets" message; just re-run setcap.
   - This grants raw-socket access to *every* process using that interpreter.

3. Add a `PipeInterface` to your `~/.reticulum/config` file on **both** the server and the client.

   Use an **absolute interpreter path** in `command` — RNS spawns the process with
   the cwd of rnsd, so relative paths and tools that depend on cwd (`uv run`)
   will break depending on where rnsd was started.

### Client config

```
[[ICMP Interface]]
    type = PipeInterface
    enabled = True
    command = /absolute/path/to/python /absolute/path/to/icmp_tunnel.py --dst <server-ip> client
    # or you can use my public server at rns.obomba.tech

    # Optional: delay before respawn in seconds
    respawn_delay = 2
    name = ICMP Interface
```

### Server config

```
[[ICMP Interface]]
    type = PipeInterface
    enabled = True
    command = /absolute/path/to/python /root/icmp/icmp_tunnel.py server --iface <eth0 or other interface name>

    # Optional: delay before respawn in seconds
    respawn_delay = 2
    name = ICMP Interface
```

4. Start the Reticulum daemon:

   ```bash
   rnsd
   ```

## Behaviour notes

- Logs go to `tunnel.log` next to the script, or to the path in the
  `ICMP_TUNNEL_LOG_FILE` environment variable. The file handler needs write
  access; on failure the tunnel falls back to stderr only.
- On start the server tries to disable kernel ICMP echo replies
  (`net.ipv4.icmp_echo_ignore_all=1`), which needs root or `CAP_NET_ADMIN`.
  Without it (e.g. in a container with only `CAP_NET_RAW`), the kernel also
  answers client pings with normal echo replies — the client filters those
  out, so this is harmless, but the host stays pingable.
- Throughput is bounded by `PING_INTERVAL`, `CLIENT_BURST` and
  `SERVER_MAX_REPLIES` at the top of the script (defaults: client pings every
  0.5 s and bursts up to 8 packets; the server piggybacks up to 8 queued
  messages per received ping).
- The client self-heals after network outages (suspend/resume, interface
  flaps, route changes): sends back off (up to `SEND_BACKOFF_CAP` between
  probes) while the interface is down, the capture socket is reopened every
  `SNIFF_CYCLE` seconds with a freshly resolved route, and if the server
  stays silent past `RECV_STALE_WARN` + `RECV_STALE_DIE` while sends still
  succeed, the client exits so the RNS PipeInterface respawns it with clean
  state.
