import datetime
import errno
import logging
import logging.handlers
import os
import signal
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntFlag, IntEnum
from queue import Queue
from threading import Thread, Event
from time import sleep
from typing import Iterable, Tuple, List

from scapy.all import IP, ICMP, send, Raw
from scapy.config import conf
from scapy.layers.l2 import getmacbyip, Ether
from scapy.sendrecv import sniff, sendp

ICMP_HEADER_SIZE = 8
MTU = 1300

# Setup file logging with rotation
def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create rotating file handler (1MB max size, keep 5 backup files)
    file_handler = logging.handlers.RotatingFileHandler(
        'tunnel.log',
        maxBytes=1024 * 1024,  # 1MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Create console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


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

    flags = TunnelType(payload[2])
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
        self._send_queue.put(pkt)

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

    def _handle_packet(self, pkt) -> TunnelPacket | None:
        if ICMP not in pkt:
            return None
        icmp = pkt[ICMP]
        if icmp.type not in [0, 8] or not icmp.payload:
            return None

        raw = bytes(icmp.payload)
        tunnel_packet = self.decode(raw)

        if tunnel_packet is None:
            return None
        return tunnel_packet


@dataclass
class ActiveMessage:
    active_until: datetime.datetime
    payload: bytes
    sent_to: set[str]


class Server(AbstractTunnel):
    MESSAGE_LIFETIME = datetime.timedelta(seconds=10)

    def __init__(self, iface: str, mtu: int):
        super().__init__(mtu)
        self._sniff_thread: Thread | None = None
        self._stop_event = Event()
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
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
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
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.logger.warning(f"Failed to enable system pings: {e}")

    def start(self) -> None:
        self._disable_system_pings()

        self._sniff_thread = Thread(target=self._sniff, daemon=True)
        self._sniff_thread.start()

    def _sniff(self) -> None:
        def on_pkt(pkt):
            tunnel_packet = self._handle_packet(pkt)
            if tunnel_packet is not None:
                # send message from queue anyway
                self._reply(pkt)

                if tunnel_packet.type == TunnelType.PAYLOAD:
                    self.logger.debug("got packet: %s", str(tunnel_packet))
                    self._recv_queue.put(tunnel_packet.payload)

        sniff(filter="icmp", prn=on_pkt, store=False, stop_filter=lambda x: self._stop_event.is_set())

    def stop(self) -> None:
        self._stop_event.set()
        self._enable_system_pings()
        if self._sniff_thread is not None:
            self._sniff_thread.join()

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

        msg = self._get_message_for_reply(dst_ip)
        if msg is None:
            return
        data = msg.payload
        tunnel_packet = TunnelPacket(type=TunnelType.REPLY if data else TunnelType.EMPTY, payload=data)

        ip_pkt = (
                IP(dst=dst_ip, src=src_ip) /
                ICMP(type=0, id=icmp_id, seq=icmp_seq) /
                Raw(load=self.encode(tunnel_packet))
        )

        iface, _, gw = conf.route.route(dst_ip)
        mac = getmacbyip(gw)
        if mac:
            sendp(Ether(dst=mac) / ip_pkt, iface=iface, verbose=False)


class Client(AbstractTunnel):
    def __init__(self, dst: str, mtu: int):
        super().__init__(mtu)
        self.dst = dst
        self._sniff_thread: Thread | None = None
        self._ping_thread: Thread | None = None

    def start(self) -> None:
        self._ping_thread = Thread(target=self._ping, daemon=True)
        self._sniff_thread = Thread(target=self._sniff, daemon=True)

        self._sniff_thread.start()
        self._ping_thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _sniff(self) -> None:
        def on_pkt(pkt):
            tunnel_packet = self._handle_packet(pkt)
            if tunnel_packet is not None:
                if tunnel_packet.type == TunnelType.REPLY:
                    self.logger.debug("got packet: %s", str(tunnel_packet))
                    self._recv_queue.put(tunnel_packet.payload)

        sniff(filter="icmp", prn=on_pkt, store=False, stop_filter=lambda x: self._stop_event.is_set())

    def _ping(self) -> None:
        while not self._stop_event.is_set():
            sleep(1)
            if self._send_queue.empty():
                self._send_empty()
            else:
                self._send_data(self._send_queue.get(block=False))

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
    import select
    import threading
    import queue

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

    import sys


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
                        # Пишем напрямую в файловый дескриптор
                        os.write(stdout_fd, received_data)
                    except OSError as e:
                        if e.errno == errno.EPIPE:
                            # Broken pipe - выход
                            # logger.error("Broken pipe: программа A закрыла чтение")
                            stop_event.set()
                            return
                        else:
                            # logger.error("Ошибка записи: %s", e)
                            stop_event.set()
                            return

            except Exception as e:
                logger.error("tunnel.recv() error: %s", e)
                return


    def read_stdin_bytes():
        """Read bytes from stdin non-blockingly"""
        try:
            data = os.read(0, MTU)  # FD 0 — это stdin
            if not data:
                return None
            return data
        except KeyboardInterrupt:
            pass


    try:
        if args.mode == "server":
            if args.dst:
                parser.error("--dst is not used in server mode")

            if not args.iface:
                parser.error("--iface must be set in server mode")

            server = Server(iface=args.iface, mtu=args.mtu)
            server.start()
            logger.info(f"Server started on interface {args.iface} with MTU={args.mtu}")

            stop_event = threading.Event()
            receive_thread = threading.Thread(target=receive_messages, args=(server, stop_event), daemon=True)
            receive_thread.start()

            try:
                while True:
                    message = read_stdin_bytes()
                    if message:
                        server.send(message)

            except KeyboardInterrupt:
                logger.info("Stopping server...")
                stop_event.set()
                server.stop()

        elif args.mode == "client":
            if not args.dst:
                parser.error("--dst is required for client mode")

            client = Client(dst=args.dst, mtu=args.mtu)
            client.start()
            logger.info(f"Client started, connecting to {args.dst} with MTU={args.mtu}")

            stop_event = threading.Event()
            receive_thread = threading.Thread(target=receive_messages, args=(client, stop_event), daemon=True)
            receive_thread.start()

            try:
                while True:
                    message = read_stdin_bytes()
                    if message:
                        client.send(message)

            except KeyboardInterrupt:
                logger.info("Stopping client...")
                stop_event.set()
                client.stop()

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
