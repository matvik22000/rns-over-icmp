import datetime
import errno
import logging
import logging.handlers
import os
import signal
import socket
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from queue import Empty, Queue
from threading import Thread, Event
from time import monotonic, sleep
from typing import Iterable, List

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, getmacbyip
from scapy.packet import Raw
from scapy.config import conf
from scapy.sendrecv import send, sniff, sendp

ICMP_HEADER_SIZE = 8
MTU = 1300

# Transport tuning:
#   PING_INTERVAL      - how often the client pings when idle (keepalive + poll)
#   CLIENT_BURST       - max data packets the client sends per tick
#   SERVER_MAX_REPLIES - max queued messages the server piggybacks on one ping
PING_INTERVAL = 0.5
CLIENT_BURST = 8
SERVER_MAX_REPLIES = 8

# Recovery tuning:
#   SEND_BACKOFF_CAP - max interval between send attempts while network is down
#   SEND_LOG_EVERY   - log a "still down" line every N failed send attempts
#   RECV_STALE_WARN  - reply silence before suspecting a stale route/socket
#   RECV_STALE_DIE   - extra silence past WARN before exiting for respawn
#   SNIFF_CYCLE      - max lifetime of one capture socket before reopening
SEND_BACKOFF_CAP = 10.0
SEND_LOG_EVERY = 20
RECV_STALE_WARN = 30.0
RECV_STALE_DIE = 90.0
SNIFF_CYCLE = 30.0


def _log_file_path() -> str:
    env = os.getenv('ICMP_TUNNEL_LOG_FILE')
    if env:
        return env
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tunnel.log')


# Setup file logging with rotation
def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create console handler (stderr) first, so a broken log file path
    # still leaves us with usable output
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Create rotating file handler (1MB max size, keep 5 backup files)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            _log_file_path(),
            maxBytes=1024 * 1024,  # 1MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as e:
        logging.getLogger(__name__).warning(f"No file logging ({e}); stderr only")


# Setup logging at module level
setup_logging()


class TunnelType(IntEnum):
    EMPTY = 0x00
    PAYLOAD = 0x01
    REPLY = 0x02


@dataclass
class TunnelPacket:
    MAGIC = b'\xFA\xCE'
    ICMP_ID = 1530
    type: TunnelType
    payload: bytes

    def __bytes__(self) -> bytes:
        return self.MAGIC + bytes([self.type]) + self.payload

    def __str__(self):
        hex_payload = ' '.join(f'{b:02x}' for b in self.payload)
        return f"TunnelPacket(type={self.type.name}, payload=[{hex_payload}])"


def _decode_bytes_to_packet(payload: bytes) -> TunnelPacket | None:
    if len(payload) < 3 or not payload.startswith(TunnelPacket.MAGIC):
        return None

    try:
        flags = TunnelType(payload[2])
    except ValueError:
        # Unknown type byte: not one of ours, ignore instead of raising
        return None

    packet_payload = payload[3:]

    return TunnelPacket(type=flags, payload=packet_payload)


class AbstractTunnel(ABC):
    def __init__(self, mtu: int):
        self.mtu = mtu
        self._recv_queue: Queue[bytes] = Queue()
        self._send_queue: Queue[bytes] = Queue()
        self._stop_event = Event()
        self.logger = logging.getLogger(self.__class__.__name__)

    def send(self, pkt: bytes) -> None:
        # Frames come from RNS as complete HDLC frames; dropping one keeps the
        # stream framed (RNS resyncs on flags), while dying would leave RNS
        # waiting on a pipe nobody reads until it respawns us.
        if len(pkt) + 3 > self.mtu - ICMP_HEADER_SIZE:
            self.logger.error(
                f"outbound frame too large ({len(pkt)}+3 bytes, limit "
                f"{self.mtu - ICMP_HEADER_SIZE}); dropping - lower the RNS "
                f"interface mtu or raise tunnel --mtu"
            )
            return
        self._send_queue.put(pkt)

    def die(self, msg: str) -> None:
        # Protocol-uncorrectable errors: exit loudly so the supervisor
        # (RNS PipeInterface) respawns us with clean state and the error
        # is visible in the RNS log.
        self.logger.critical(msg)
        logging.shutdown()
        os._exit(1)

    def recv(self) -> Iterable[bytes]:
        while True:
            yield self._recv_queue.get(block=True)

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    def encode(self, packet: TunnelPacket) -> bytes:
        payload = bytes(packet)
        if len(payload) > self.mtu - ICMP_HEADER_SIZE:
            raise ValueError(f"payload too large ({len(payload)} > {self.mtu} - {ICMP_HEADER_SIZE})")
        return payload

    def decode(self, payload: bytes) -> TunnelPacket | None:
        return _decode_bytes_to_packet(payload)

    def _sniff_loop(self, on_pkt, iface: str | None = None, bpf: str | None = None,
                    timeout: float | None = None) -> None:
        kwargs = dict(
            prn=on_pkt,
            store=False,
            stop_filter=lambda x: self._stop_event.is_set(),
        )
        if timeout:
            kwargs["timeout"] = timeout
        if iface:
            kwargs["iface"] = iface

        use_filter = bpf is not None
        while not self._stop_event.is_set():
            try:
                if use_filter:
                    sniff(filter=bpf, **kwargs)
                else:
                    sniff(**kwargs)
                # Returned normally: stop request or timeout expiry. The
                # caller decides whether to reopen (it may want to
                # re-resolve the route first).
                return
            except Exception as e:
                if isinstance(e, OSError) and e.errno in (errno.EPERM, errno.EACCES):
                    self.die("cannot open capture socket (missing cap_net_raw or libpcap?)")
                if use_filter:
                    # Missing libpcap makes BPF filters impossible; fall back
                    # to unfiltered and let on_pkt do the filtering
                    self.logger.warning(f"sniff with filter failed ({e}); retrying unfiltered")
                    use_filter = False
                    continue
                self.logger.warning(f"capture failed ({e}); retrying in 5s")
                if self._stop_event.wait(5):
                    return

    def _handle_packet(self, pkt) -> TunnelPacket | None:
        if ICMP not in pkt:
            return None
        icmp = pkt[ICMP]
        if not icmp.payload:
            return None

        return self.decode(bytes(icmp.payload))


@dataclass
class ActiveMessage:
    active_until: datetime.datetime
    payload: bytes
    sent_to: set[str]


class Server(AbstractTunnel):
    MESSAGE_LIFETIME = datetime.timedelta(seconds=10)
    MAX_REPLIES_PER_PING = SERVER_MAX_REPLIES

    def __init__(self, iface: str, mtu: int):
        super().__init__(mtu)
        self._sniff_thread: Thread | None = None
        self.iface = iface
        self.active_messages: List[ActiveMessage] = []  # list of messages, that should be sent

    def _disable_system_pings(self) -> None:
        """Disable system ping responses on Linux"""
        import platform
        import subprocess

        if platform.system() != 'Linux':
            self.logger.debug("Not on Linux, skipping ping disable")
            return

        try:
            # Disable ICMP echo responses
            subprocess.run(['sysctl', '-w', 'net.ipv4.icmp_echo_ignore_all=1'],
                           check=True, capture_output=True)
            self.logger.info("Disabled system ICMP echo responses")
        except (subprocess.CalledProcessError, FileNotFoundError, PermissionError) as e:
            self.logger.warning(f"Failed to disable system pings: {e}")

    def _enable_system_pings(self) -> None:
        """Enable system ping responses on Linux"""
        import platform
        import subprocess

        if platform.system() != 'Linux':
            self.logger.debug("Not on Linux, skipping ping enable")
            return

        try:
            # Enable ICMP echo responses
            subprocess.run(['sysctl', '-w', 'net.ipv4.icmp_echo_ignore_all=0'],
                           check=True, capture_output=True)
            self.logger.info("Enabled system ICMP echo responses")
        except (subprocess.CalledProcessError, FileNotFoundError, PermissionError) as e:
            self.logger.warning(f"Failed to enable system pings: {e}")

    def start(self) -> None:
        self._disable_system_pings()

        self._sniff_thread = Thread(target=self._sniff, daemon=True)
        self._sniff_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._enable_system_pings()
        if self._sniff_thread is not None:
            self._sniff_thread.join(timeout=5)

    def _sniff(self) -> None:
        def on_pkt(pkt):
            try:
                if ICMP not in pkt:
                    return
                icmp = pkt[ICMP]
                # Only client echo requests; our own replies (type 0) must be
                # ignored or we would answer ourselves in a loop
                if icmp.type != 8:
                    return
                tunnel_packet = self.decode(bytes(icmp.payload)) if icmp.payload else None
                if tunnel_packet is None:
                    return

                if tunnel_packet.type == TunnelType.PAYLOAD:
                    self.logger.debug("got packet: %s", str(tunnel_packet))
                    self._recv_queue.put(tunnel_packet.payload)

                # answer every request, piggybacking queued messages
                self._reply(pkt)
            except Exception:
                self.logger.exception("error handling incoming packet")

        self._sniff_loop(on_pkt, iface=self.iface, bpf="icmp")

    def _get_message_for_reply(self, dst: str) -> ActiveMessage | None:
        while not self._send_queue.empty():
            self.active_messages.append(ActiveMessage(
                active_until=datetime.datetime.now() + self.MESSAGE_LIFETIME,
                payload=self._send_queue.get(),
                sent_to=set(),
            ))
        self.active_messages = [m for m in self.active_messages if m.active_until > datetime.datetime.now()]

        for msg in self.active_messages:
            if dst in msg.sent_to:
                continue
            msg.sent_to.add(dst)
            return msg
        return None

    def _reply(self, pkt):
        dst_ip = pkt[IP].src
        src_ip = pkt[IP].dst
        icmp_id = pkt[ICMP].id
        icmp_seq = pkt[ICMP].seq

        # Drain up to MAX_REPLIES_PER_PING queued messages per received ping,
        # so throughput is not limited to one packet per client ping
        for i in range(self.MAX_REPLIES_PER_PING):
            msg = self._get_message_for_reply(dst_ip)
            if msg is None:
                return
            self._send_reply(dst_ip, src_ip, icmp_id, icmp_seq + i, msg.payload)

    def _send_reply(self, dst_ip: str, src_ip: str, icmp_id: int, icmp_seq: int, data: bytes) -> None:
        tunnel_packet = TunnelPacket(type=TunnelType.REPLY if data else TunnelType.EMPTY, payload=data)

        ip_pkt = (
                IP(dst=dst_ip, src=src_ip) /
                ICMP(type=0, id=icmp_id, seq=icmp_seq) /
                Raw(load=self.encode(tunnel_packet))
        )

        try:
            # conf.route.route() returns (iface, src_addr, gw) - the gateway
            # is the THIRD element, not the second
            iface, _, gw = conf.route.route(dst_ip)
            mac = getmacbyip(gw or dst_ip)
            if not mac:
                self.logger.warning(f"no MAC for {gw or dst_ip}, dropping reply")
                return
            sendp(Ether(dst=mac) / ip_pkt, iface=iface, verbose=False)
        except Exception:
            self.logger.exception(f"failed to send reply to {dst_ip}")


class Client(AbstractTunnel):
    def __init__(self, dst: str, mtu: int):
        super().__init__(mtu)
        self.dst = dst
        try:
            self.peer_ip = socket.gethostbyname(dst)
        except OSError:
            self.die(f"cannot resolve destination {dst!r}")
        self._sniff_thread: Thread | None = None
        self._ping_thread: Thread | None = None
        # Receive-path health tracking (monotonic seconds)
        self._last_rx = monotonic()
        self._stale_since: float | None = None

    def start(self) -> None:
        self._ping_thread = Thread(target=self._ping, daemon=True)
        self._sniff_thread = Thread(target=self._sniff, daemon=True)

        self._sniff_thread.start()
        self._ping_thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _sniff(self) -> None:
        def on_pkt(pkt):
            try:
                if ICMP not in pkt:
                    return
                icmp = pkt[ICMP]
                # Only echo replies from our server. The id check keeps other
                # tunnels' or tools' MAGIC-looking traffic out.
                if icmp.type != 0 or icmp.id != TunnelPacket.ICMP_ID:
                    return
                tunnel_packet = self.decode(bytes(icmp.payload)) if icmp.payload else None
                if tunnel_packet is None:
                    return
                if pkt[IP].src != self.peer_ip:
                    return

                # Any reply (EMPTY included) proves the receive path is alive
                self._last_rx = monotonic()

                if tunnel_packet.type == TunnelType.REPLY:
                    self.logger.debug("got packet: %s", str(tunnel_packet))
                    self._recv_queue.put(tunnel_packet.payload)
            except Exception:
                self.logger.exception("error handling incoming packet")

        bpf = f"icmp and src host {self.peer_ip}"
        while not self._stop_event.is_set():
            # Re-resolve the interface on every reopen so a route or
            # interface change during an outage is picked up without a
            # restart; otherwise a socket opened before the outage can stay
            # silently bound to a dead interface forever
            try:
                iface, _, _ = conf.route.route(self.peer_ip)
            except Exception:
                iface = None

            self._sniff_loop(on_pkt, iface=iface, bpf=bpf, timeout=SNIFF_CYCLE)

    def _ping(self) -> None:
        failures = 0
        while not self._stop_event.is_set():
            try:
                sent = 0
                # Send immediately and drain the queue in bursts instead of
                # at most one packet per second
                while sent < CLIENT_BURST and not self._send_queue.empty():
                    self._send_data(self._send_queue.get(block=False))
                    sent += 1
                if sent == 0:
                    self._send_empty()
                if failures:
                    self.logger.info(f"network recovered after {failures} failed send attempts")
                    failures = 0
                    # Replies were blocked for as long as sends were; restart
                    # the receive watchdog from here
                    self._last_rx = monotonic()
                    self._stale_since = None
            except OSError as e:
                if e.errno in (errno.EPERM, errno.EACCES):
                    self.die(
                        f"no permission for raw sockets ({e}); grant "
                        f"cap_net_raw,cap_net_admin to the python binary via setcap"
                    )
                failures += 1
                if failures == 1:
                    self.logger.warning(f"network down ({e}); will retry")
                elif failures % SEND_LOG_EVERY == 0:
                    self.logger.warning(f"network still down after {failures} attempts ({e})")
            except Empty:
                pass
            except Exception:
                failures += 1
                self.logger.exception("send failed")

            self._watch_replies(failures == 0)

            # Back off while the network is down so we do not flood the log,
            # but keep probing so we resume within SEND_BACKOFF_CAP of the
            # network coming back
            if failures:
                sleep(min(SEND_BACKOFF_CAP, PING_INTERVAL * 2 ** min(failures, 6)))
            else:
                sleep(PING_INTERVAL)

    def _watch_replies(self, sending_ok: bool) -> None:
        """Detect a silently dead receive path (stale capture socket or route
        after suspend or an interface change) and recover."""
        now = monotonic()
        silent_for = now - self._last_rx
        if silent_for <= RECV_STALE_WARN:
            self._stale_since = None
            return

        if self._stale_since is None:
            self._stale_since = now
            try:
                # The scapy routing table is built at startup and goes stale
                # when interfaces flap or the default route changes
                conf.route.resync()
            except Exception:
                pass
            self.logger.warning(f"no tunnel replies for {int(silent_for)}s; re-resolved routes")
        elif sending_ok and now - self._stale_since > RECV_STALE_DIE:
            # Sends succeed but nothing comes back: the capture socket is
            # bound to a dead interface. Exit so the RNS PipeInterface
            # respawns us with clean state.
            self.die(f"no tunnel replies for {int(silent_for)}s; exiting for respawn")

    def _send_empty(self):
        tunnel_packet = TunnelPacket(type=TunnelType.EMPTY, payload=bytes())
        pkt = IP(dst=self.dst) / ICMP(type=8, id=TunnelPacket.ICMP_ID) / Raw(load=self.encode(tunnel_packet))
        send(pkt, verbose=False)

    def _send_data(self, data: bytes) -> None:
        self.logger.debug("data to %s: %s", self.dst, data)

        tunnel_packet = TunnelPacket(type=TunnelType.PAYLOAD, payload=data)
        pkt = IP(dst=self.dst) / ICMP(type=8, id=TunnelPacket.ICMP_ID) / Raw(load=self.encode(tunnel_packet))
        send(pkt, verbose=False)


if __name__ == "__main__":
    import argparse
    import threading

    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="ICMP Tunnel - Server/Client")
    parser.add_argument("mode", choices=["server", "client"], help="Run mode: server or client")
    parser.add_argument("--mtu", type=int, default=MTU, help=f"MTU size (default: {MTU})")
    parser.add_argument("--dst", type=str, help="Destination IP (required for client mode)")
    parser.add_argument("--iface", type=str, help="Network interface (default: eth0)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Adjust console logging level based on verbose flag
    if args.verbose:
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler,
                                                                             logging.handlers.RotatingFileHandler):
                handler.setLevel(logging.DEBUG)

    def receive_messages(tunnel, stop_event):
        """Thread function to receive and forward raw bytes to stdout."""

        # Открываем stdout один раз, а не на каждый пакет
        stdout_fd = sys.stdout.fileno()

        while not stop_event.is_set():
            try:
                for received_data in tunnel.recv():
                    if not received_data:
                        continue

                    try:
                        # Пишем напрямую в файловый дескриптор, доезаписывая
                        # при частичной записи
                        view = memoryview(received_data)
                        while view:
                            written = os.write(stdout_fd, view)
                            view = view[written:]
                    except OSError as e:
                        if e.errno == errno.EPIPE:
                            # Broken pipe - выход
                            stop_event.set()
                            return
                        else:
                            stop_event.set()
                            return

            except Exception as e:
                logger.error("tunnel.recv() error: %s", e)
                return


    def read_stdin_bytes():
        """Read bytes from stdin; returns None on EOF"""
        try:
            return os.read(0, 1024) or None
        except OSError:
            return None


    def request_stop(tunnel, stop_event):
        stop_event.set()
        tunnel.stop()


    def on_sigterm(*_):
        raise KeyboardInterrupt


    try:
        if args.mode == "server":
            if args.dst:
                parser.error("--dst is not used in server mode")

            if not args.iface:
                parser.error("--iface must be set in server mode")

            logger.info(f"Starting server on interface {args.iface} with MTU={args.mtu}...")
            server = Server(iface=args.iface, mtu=args.mtu)
            server.start()

            stop_event = threading.Event()
            receive_thread = threading.Thread(target=receive_messages, args=(server, stop_event), daemon=True)
            receive_thread.start()

            signal.signal(signal.SIGTERM, on_sigterm)

            try:
                while True:
                    message = read_stdin_bytes()
                    if message is None:
                        logger.info("stdin closed, stopping server")
                        break
                    server.send(message)

            except KeyboardInterrupt:
                logger.info("Stopping server...")
            finally:
                request_stop(server, stop_event)

        elif args.mode == "client":
            if not args.dst:
                parser.error("--dst is required for client mode")

            client = Client(dst=args.dst, mtu=args.mtu)
            client.start()
            logger.info(f"Client started, connecting to {args.dst} ({client.peer_ip}) with MTU={args.mtu}")

            stop_event = threading.Event()
            receive_thread = threading.Thread(target=receive_messages, args=(client, stop_event), daemon=True)
            receive_thread.start()

            signal.signal(signal.SIGTERM, on_sigterm)

            try:
                while True:
                    message = read_stdin_bytes()
                    if message is None:
                        logger.info("stdin closed, stopping client")
                        break
                    client.send(message)

            except KeyboardInterrupt:
                logger.info("Stopping client...")
            finally:
                request_stop(client, stop_event)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception(f"Error: {e}")
        sys.exit(1)
