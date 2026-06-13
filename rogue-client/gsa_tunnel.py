#!/usr/bin/env python3

import grpc
import uuid
import time
import struct
import socket
import threading
import logging
import argparse
import json
import base64
import os
import sys
import signal
import fcntl
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from queue import Queue, Empty

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztna_v2_pb2
import ztna_v2_pb2_grpc

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('gsa-tunnel')

EDGE_TEMPLATE = "{tenant}.private.client.globalsecureaccess.microsoft.com:443"
DEFAULT_TENANT = ""
DEVICE_ID = "00000000-0000-0000-0000-000000000000"
GSA_DNS_SERVER = "6.6.255.254"
TUN_NAME = "gsa0"
TUN_ADDR = "10.128.0.2"
TUN_NETMASK = "255.255.255.0"
TUN_MTU = 1400

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

DEFAULT_ROUTES = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]

AUD_PORTO = "79486f61-d9f0-430e-9f7c-1713c8d9a2f9"
AUD_APS = "b3fa0115-39b3-4bec-8cc6-8c4fcd33e69d"
AUD_TUNNEL = "e92b9b37-1b47-4c01-9fbc-91d84450870e"

def decode_jwt_payload(token: str) -> dict:
    parts = token.split('.')
    if len(parts) < 2:
        return {}
    payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))

def extract_tokens_from_dump(path: str) -> Dict[str, str]:
    with open(path) as f:
        content = f.read()

    tokens_by_aud = {}
    for line in content.split('\n'):
        for part in line.split():
            if not part.startswith('eyJ') or '.' not in part:
                continue
            try:
                claims = decode_jwt_payload(part)
                aud = claims.get('aud', '')
                exp = claims.get('exp', 0)
                if aud and (aud not in tokens_by_aud or exp > decode_jwt_payload(tokens_by_aud[aud]).get('exp', 0)):
                    tokens_by_aud[aud] = part
            except Exception:
                continue

    return tokens_by_aud

def load_token_file(path: str) -> str:
    with open(path) as f:
        return f.read().strip()

def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

class TunDevice:
    def __init__(self, name: str = TUN_NAME, addr: str = TUN_ADDR, mtu: int = TUN_MTU):
        self.name = name
        self.addr = addr
        self.mtu = mtu
        self.fd = None

    def open(self):
        subprocess.run(['ip', 'link', 'delete', self.name],
                       capture_output=True, timeout=5)
        self.fd = os.open('/dev/net/tun', os.O_RDWR)
        ifr = struct.pack('16sH', self.name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        logger.info(f"TUN device '{self.name}' created")

    def configure(self, routes: list):
        self._saved_routes = []
        cmds = [
            ['ip', 'addr', 'add', f'{self.addr}/24', 'dev', self.name],
            ['ip', 'link', 'set', 'dev', self.name, 'mtu', str(self.mtu)],
            ['ip', 'link', 'set', 'dev', self.name, 'up'],
        ]
        for cmd in cmds:
            ret = subprocess.run(cmd, capture_output=True, text=True)
            if ret.returncode != 0 and 'File exists' not in ret.stderr:
                logger.warning(f"cmd failed: {' '.join(cmd)} — {ret.stderr.strip()}")

        for route in routes:
            # Save existing route for restoration on shutdown
            existing = subprocess.run(
                ['ip', 'route', 'show', route],
                capture_output=True, text=True
            )
            if existing.stdout.strip():
                self._saved_routes.append(existing.stdout.strip())

            # Use 'replace' to override any existing route
            ret = subprocess.run(
                ['ip', 'route', 'replace', route, 'dev', self.name],
                capture_output=True, text=True
            )
            if ret.returncode != 0:
                logger.warning(f"route failed: {route} — {ret.stderr.strip()}")
            else:
                logger.info(f"  Route: {route} → {self.name}")

        logger.info(f"TUN configured: {self.addr}/24, MTU={self.mtu}, {len(routes)} routes forced through tunnel")

    def read(self) -> bytes:
        return os.read(self.fd, self.mtu + 100)

    def write(self, data: bytes):
        os.write(self.fd, data)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        for route_line in getattr(self, '_saved_routes', []):
            subprocess.run(
                ['ip', 'route', 'replace'] + route_line.split(),
                capture_output=True, timeout=5
            )
            logger.info(f"  Restored route: {route_line}")
        subprocess.run(['ip', 'link', 'delete', self.name],
                       capture_output=True, timeout=5)
        logger.info(f"TUN device '{self.name}' removed")


@dataclass
class FlowState:
    key: Tuple
    correlation_id: str
    send_queue: Queue = field(default_factory=Queue)
    active: bool = True
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    thread: Optional[threading.Thread] = None

class GSATunnel:
    def __init__(self, tunnel_token: str, porto_token: str, aps_token: str,
                 edge: str, routes: list, tun_addr: str = TUN_ADDR,
                 dns_override: str = None):
        self.tunnel_token = tunnel_token
        self.porto_token = porto_token
        self.aps_token = aps_token
        self.edge = edge
        self.routes = routes
        self.tun_addr = tun_addr
        self.dns_server = dns_override or GSA_DNS_SERVER

        self.channel = None
        self.stub = None
        self.tunnel_id = None
        self.control_active = False
        self.running = False
        self.msg_queue = []
        self.flow_auth_results: Dict[str, str] = {}

        self.tun = TunDevice(addr=tun_addr)
        self.flows: Dict[Tuple, FlowState] = {}
        self.flows_lock = threading.Lock()

        self.packets_in = 0
        self.packets_out = 0
        self.flows_created = 0

    def _make_device_info(self):
        return ztna_v2_pb2.ClientDeviceInfo(
            client_agent_version="GsaTunnelSvc/2.1.1.0",
            client_os_type="Windows",
            client_os_version="10.0.26100",
            client_device_id=DEVICE_ID,
            client_os_name="Windows 11 Enterprise",
            client_device_name="GSA-Client",
            client_os_architecture="x86_64",
        )

    def connect(self) -> bool:
        logger.info(f"Connecting to {self.edge}")
        try:
            creds = grpc.ssl_channel_credentials()
            self.channel = grpc.secure_channel(self.edge, creds, options=[
                ('grpc.keepalive_time_ms', 30000),
                ('grpc.keepalive_permit_without_calls', 1),
                ('grpc.max_receive_message_length', 16 * 1024 * 1024),
            ])
            grpc.channel_ready_future(self.channel).result(timeout=10.0)
            self.stub = ztna_v2_pb2_grpc.ZtnaStub(self.channel)
            logger.info("gRPC channel ready")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def establish_tunnel(self) -> bool:
        self.control_active = True

        def control_gen():
            yield ztna_v2_pb2.ClientControlMessage(
                correlation_vector=f"cv.{uuid.uuid4().hex[:16]}.0",
                create_tunnel=ztna_v2_pb2.CreateTunnelMessage(
                    tunnel_token=self.tunnel_token,
                    agent_metadata=self._make_device_info(),
                )
            )
            while self.control_active:
                if self.msg_queue:
                    yield self.msg_queue.pop(0)
                else:
                    time.sleep(0.05)

        try:
            self._responses = self.stub.CreateControlChannel(control_gen())
            resp = next(self._responses)
            if resp.WhichOneof('payload') != 'tunnel_created':
                payload_type = resp.WhichOneof('payload')
                if payload_type == 'tunnel_authentication_required':
                    logger.error("Tunnel auth required — token may be expired")
                else:
                    logger.error(f"Tunnel creation failed: {payload_type}")
                return False

            self.tunnel_id = resp.tunnel_created.tunnel_id
            region = resp.tunnel_created.azure_region_display_name
            geo = resp.tunnel_created.server_geo_location
            logger.info(f"Tunnel established: {self.tunnel_id[:12]}...")
            logger.info(f"  Region: {region} | Geo: {geo}")

            threading.Thread(target=self._control_reader, daemon=True).start()
            return True

        except grpc.RpcError as e:
            logger.error(f"Control channel error: {e.code()} — {e.details()}")
            return False

    def _control_reader(self):
        try:
            for r in self._responses:
                w = r.WhichOneof('payload')
                if w == 'flow_authentication_success':
                    cid = r.flow_authentication_success.correlation_id or '_empty'
                    self.flow_auth_results[cid] = 'success'
                elif w == 'flow_authentication_failure':
                    cid = r.flow_authentication_failure.correlation_id or '_empty'
                    self.flow_auth_results[cid] = 'failure'
                    logger.debug(f"Flow auth failure: {cid[:8]}")
                elif w == 'flow_closed':
                    fc = r.flow_closed
                    cid = fc.correlation_id
                    detail = ""
                    if fc.reason:
                        detail = f" [{fc.reason.close_status_code}] {fc.reason.detailed_description}"
                    logger.debug(f"Flow closed: {cid[:8]}{detail}")
                    self._cleanup_flow_by_cid(cid)
                elif w == 'tunnel_closed':
                    logger.warning(f"Tunnel closed by server: {r.tunnel_closed.error_message}")
                    self.control_active = False
                    self.running = False
                    break
                else:
                    logger.debug(f"Control msg: {w}")
        except grpc.RpcError:
            if self.running:
                logger.warning("Control channel disconnected")
                self.running = False

    def _cleanup_flow_by_cid(self, cid: str):
        with self.flows_lock:
            for key, flow in list(self.flows.items()):
                if flow.correlation_id == cid:
                    flow.active = False
                    flow.send_queue.put(None)
                    del self.flows[key]
                    break

    def _pre_auth_flow(self, meta, timeout=3.0) -> str:
        cid = meta.correlation_id
        self.flow_auth_results.pop(cid, None)
        self.flow_auth_results.pop('_empty', None)

        self.msg_queue.append(ztna_v2_pb2.ClientControlMessage(
            correlation_vector=f"cv.{uuid.uuid4().hex[:16]}.0",
            flow_authentication_request=ztna_v2_pb2.FlowAuthenticationRequest(metadata=meta)
        ))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cid in self.flow_auth_results:
                return self.flow_auth_results.pop(cid)
            if '_empty' in self.flow_auth_results:
                return self.flow_auth_results.pop('_empty')
            time.sleep(0.02)
        return 'timeout'

    def _get_flow_key(self, packet: bytes) -> Optional[Tuple]:
        if len(packet) < 20:
            return None
        version = (packet[0] >> 4) & 0xF
        if version != 4:
            return None

        proto = packet[9]
        if proto not in (6, 17):
            return None

        dst_ip = socket.inet_ntoa(packet[16:20])

        first_octet = packet[16]
        if first_octet >= 224:
            return None

        ihl = (packet[0] & 0xF) * 4
        transport = packet[ihl:]
        if len(transport) < 4:
            return None

        dst_port = struct.unpack('!H', transport[2:4])[0]

        # For TCP, include src_port to distinguish connections
        if proto == 6:
            src_port = struct.unpack('!H', transport[0:2])[0]
            return (dst_ip, dst_port, proto, src_port)

        return (dst_ip, dst_port, proto)

    def _create_flow(self, key: Tuple, first_packet: bytes) -> Optional[FlowState]:
        dst_ip = key[0]
        dst_port = key[1]
        proto = key[2]

        cid = str(uuid.uuid4())
        meta = ztna_v2_pb2.ClientFlowMetadata(
            correlation_id=cid,
            tunnel_id=self.tunnel_id,
            destination_ip=dst_ip,
            destination_host="",
            destination_port=dst_port,
            protocol=proto,
            client_resolved_ips="",
            client_invoked_process_name="svchost.exe",
            app_token=self.porto_token,
        )

        auth_result = self._pre_auth_flow(meta)
        if auth_result == 'failure':
            logger.debug(f"Flow auth denied: {dst_ip}:{dst_port}/{proto}")
            return None

        flow_state = FlowState(key=key, correlation_id=cid)
        flow_state.send_queue.put(first_packet)

        def run_flow():
            self._flow_worker(flow_state, meta)

        flow_state.thread = threading.Thread(target=run_flow, daemon=True)
        flow_state.thread.start()
        self.flows_created += 1
        return flow_state

    def _flow_worker(self, state: FlowState, meta):
        def flow_gen():
            yield ztna_v2_pb2.ClientFlowMessage(metadata=meta)
            time.sleep(0.1)
            while state.active:
                try:
                    pkt = state.send_queue.get(timeout=0.5)
                    if pkt is None:
                        break
                    yield ztna_v2_pb2.ClientFlowMessage(packet=pkt)
                    state.last_activity = time.monotonic()
                except Empty:
                    if time.monotonic() - state.last_activity > 120:
                        break

        try:
            bearer = self.aps_token or self.porto_token
            grpc_meta = [('authorization', f'Bearer {bearer}')]
            stream = self.stub.CreateFlow(flow_gen(), metadata=grpc_meta)

            for resp in stream:
                if not state.active:
                    break
                if resp.packet:
                    state.last_activity = time.monotonic()
                    self.tun.write(resp.packet)
                    self.packets_in += 1

        except grpc.RpcError as e:
            code = e.code()
            if code != grpc.StatusCode.CANCELLED:
                logger.debug(f"Flow {state.correlation_id[:8]} ended: {code}")
        finally:
            state.active = False
            with self.flows_lock:
                self.flows.pop(state.key, None)

    def _flow_cleanup(self):
        while self.running:
            time.sleep(30)
            now = time.monotonic()
            with self.flows_lock:
                stale = [k for k, f in self.flows.items()
                         if now - f.last_activity > 120]
                for k in stale:
                    self.flows[k].active = False
                    self.flows[k].send_queue.put(None)
                    del self.flows[k]
                if stale:
                    logger.debug(f"Cleaned {len(stale)} stale flows")

    def _tun_reader(self):
        while self.running:
            try:
                packet = self.tun.read()
                if not packet:
                    continue

                key = self._get_flow_key(packet)
                if key is None:
                    continue

                self.packets_out += 1

                with self.flows_lock:
                    flow = self.flows.get(key)

                if flow and flow.active:
                    flow.send_queue.put(packet)
                    flow.last_activity = time.monotonic()
                else:
                    flow = self._create_flow(key, packet)
                    if flow:
                        with self.flows_lock:
                            self.flows[key] = flow
                        logger.debug(f"New flow: {key[0]}:{key[1]}/{key[2]} ({self.flows_created})")

            except OSError as e:
                if self.running:
                    logger.error(f"TUN read error: {e}")
                break

    def _stats_printer(self):
        while self.running:
            time.sleep(60)
            with self.flows_lock:
                active = len(self.flows)
            logger.info(f"Stats: {self.packets_out} out, {self.packets_in} in, "
                       f"{active} active flows, {self.flows_created} total created")

    def setup_dns(self):
        resolv_backup = "/tmp/resolv.conf.gsa.bak"
        try:
            if not os.path.exists(resolv_backup):
                subprocess.run(['cp', '/etc/resolv.conf', resolv_backup], check=True)
            dns_conf = f"nameserver {self.dns_server}\nnameserver 8.8.8.8\n"
            with open('/etc/resolv.conf', 'w') as f:
                f.write(dns_conf)
            logger.info(f"DNS configured: {self.dns_server} (backup at {resolv_backup})")
        except PermissionError:
            logger.warning("Cannot modify /etc/resolv.conf — run as root for DNS override")
        except Exception as e:
            logger.warning(f"DNS setup failed: {e}")

    def restore_dns(self):
        resolv_backup = "/tmp/resolv.conf.gsa.bak"
        if os.path.exists(resolv_backup):
            try:
                subprocess.run(['cp', resolv_backup, '/etc/resolv.conf'], check=True)
                os.unlink(resolv_backup)
                logger.info("DNS restored")
            except Exception:
                pass

    def _resolve_edge_ip(self) -> Optional[str]:
        host = self.edge.split(':')[0]
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def run(self):
        if not self.connect():
            return 1

        if not self.establish_tunnel():
            return 1

        # Ensure edge server traffic doesn't get routed into the TUN (routing loop)
        edge_ip = self._resolve_edge_ip()
        if edge_ip:
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                    capture_output=True, text=True)
            if result.stdout.strip():
                parts = result.stdout.strip().split()
                gw_idx = parts.index('via') + 1 if 'via' in parts else -1
                dev_idx = parts.index('dev') + 1 if 'dev' in parts else -1
                if gw_idx > 0 and dev_idx > 0:
                    subprocess.run(['ip', 'route', 'add', f'{edge_ip}/32',
                                    'via', parts[gw_idx], 'dev', parts[dev_idx]],
                                   capture_output=True)
                    logger.debug(f"Edge IP {edge_ip} excluded from TUN routing")

        self.tun.open()
        self.tun.configure(self.routes)
        self.setup_dns()
        self.running = True

        logger.info("=" * 50)
        logger.info("TUNNEL ACTIVE — routing traffic through GSA")
        logger.info(f"  Interface: {TUN_NAME} ({self.tun_addr})")
        logger.info(f"  Routes: {', '.join(self.routes)}")
        logger.info(f"  DNS: {self.dns_server}")
        logger.info("  Press Ctrl+C to disconnect")
        logger.info("=" * 50)

        threading.Thread(target=self._tun_reader, daemon=True).start()
        threading.Thread(target=self._flow_cleanup, daemon=True).start()
        threading.Thread(target=self._stats_printer, daemon=True).start()

        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

        return self.shutdown()

    def shutdown(self) -> int:
        logger.info("Shutting down...")
        self.running = False
        self.control_active = False

        with self.flows_lock:
            for flow in self.flows.values():
                flow.active = False
                flow.send_queue.put(None)
            self.flows.clear()

        self.restore_dns()
        self.tun.close()

        if self.channel:
            self.channel.close()

        logger.info(f"Done. Sent {self.packets_out} packets, received {self.packets_in}")
        return 0

def main():
    parser = argparse.ArgumentParser(
        description="GSA Private Access Tunnel — route traffic through Microsoft Global Secure Access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-extract tokens from System Informer dump
  sudo python3 gsa_tunnel.py --token-file /tmp/token

  # Explicit token files
  sudo python3 gsa_tunnel.py --tunnel-token /tmp/gsa_private_token.txt \\
                              --porto-token /tmp/gsa_porto_token.txt \\
                              --aps-token /tmp/gsa_aps_token.txt

  # Custom routes only for specific subnets
  sudo python3 gsa_tunnel.py --token-file /tmp/token --routes 192.168.255.0/24,10.0.0.0/8
        """,
    )

    tok = parser.add_argument_group("Tokens")
    tok.add_argument("--token-file", default="/tmp/token",
                     help="System Informer dump with JWTs (default: /tmp/token)")
    tok.add_argument("--tunnel-token", help="Private tunnel token file (aud: e92b9b37)")
    tok.add_argument("--porto-token", help="PortoToken file (aud: 79486f61)")
    tok.add_argument("--aps-token", help="APS bearer token file (aud: b3fa0115)")

    net = parser.add_argument_group("Network")
    net.add_argument("--edge", help="Edge server (default: auto from tenant)")
    net.add_argument("--tenant", default=DEFAULT_TENANT, help="Azure tenant ID")
    net.add_argument("--routes", help="Comma-separated CIDR routes (default: RFC1918)")
    net.add_argument("--tun-addr", default=TUN_ADDR, help=f"TUN interface IP (default: {TUN_ADDR})")
    net.add_argument("--dns", help="Override DNS server IP")
    net.add_argument("--no-dns", action="store_true", help="Don't modify /etc/resolv.conf")

    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tunnel_token = None
    porto_token = None
    aps_token = None

    if args.tunnel_token:
        tunnel_token = load_token_file(args.tunnel_token)
        porto_token = load_token_file(args.porto_token) if args.porto_token else None
        aps_token = load_token_file(args.aps_token) if args.aps_token else None
    else:
        token_path = args.token_file
        if not os.path.exists(token_path):
            parser.error(f"Token file not found: {token_path}")

        logger.info(f"Parsing tokens from {token_path}")
        tokens = extract_tokens_from_dump(token_path)

        tunnel_token = tokens.get(AUD_TUNNEL)
        porto_token = tokens.get(AUD_PORTO)
        aps_token = tokens.get(AUD_APS)

        if not tunnel_token:
            parser.error(f"No tunnel token (aud={AUD_TUNNEL}) found in {token_path}")
        if not porto_token:
            parser.error(f"No PortoToken (aud={AUD_PORTO}) found in {token_path}")

        for name, tok, aud in [("Tunnel", tunnel_token, AUD_TUNNEL),
                                ("Porto", porto_token, AUD_PORTO),
                                ("APS", aps_token, AUD_APS)]:
            if tok:
                claims = decode_jwt_payload(tok)
                exp = claims.get('exp', 0)
                remaining = exp - time.time()
                status = f"expires in {int(remaining)}s" if remaining > 0 else "EXPIRED"
                logger.info(f"  {name}: aud={aud[:8]}... {status}")
            else:
                logger.warning(f"  {name}: NOT FOUND")

    if not tunnel_token or not porto_token:
        logger.error("Need at minimum: tunnel token + porto token")
        return 1

    tunnel_claims = decode_jwt_payload(tunnel_token)
    if tunnel_claims.get('exp', 0) < time.time():
        logger.error("Tunnel token EXPIRED!")
        return 1

    edge = args.edge or EDGE_TEMPLATE.format(tenant=args.tenant)
    routes = args.routes.split(',') if args.routes else DEFAULT_ROUTES

    tunnel = GSATunnel(
        tunnel_token=tunnel_token,
        porto_token=porto_token,
        aps_token=aps_token or porto_token,
        edge=edge,
        routes=routes,
        tun_addr=args.tun_addr,
        dns_override=args.dns,
    )

    if args.no_dns:
        tunnel.setup_dns = lambda: None
        tunnel.restore_dns = lambda: None

    def sig_handler(sig, frame):
        tunnel.running = False

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    return tunnel.run()

if __name__ == "__main__":
    sys.exit(main())