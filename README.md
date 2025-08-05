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

3. Add a `PipeInterface` to your `~/.reticulum/config` file on **both** the server and the client.

### Client config

```
[[ICMP Interface]]
    type = PipeInterface
    enabled = True
    command = python3 /path/to/your/icmp_tunnel.py --dst <server-ip> client
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
    command = python3 /root/icmp/icmp_tunnel.py server --iface <eth0 or other interface name>

    # Optional: delay before respawn in seconds
    respawn_delay = 2
    name = ICMP Interface
```

4. Start the Reticulum daemon:

   ```bash
   rnsd
   ```

