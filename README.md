# Tunnel Vision Toolkit

<div style="text-align:center"><img src="logo.png" alt="Logo" /></div>

Offensive security toolkit for Microsoft Global Secure Access (GSA), Microsoft's Zero Trust Network Access (ZTNA) solution. Developed as part of the research presented at **x33fcon 2026** — *"Tunnel Vision: What Microsoft's Secure Edge Can't See"*.

## Overview

Microsoft Global Secure Access is an identity-aware, cloud-delivered network security service that replaces traditional VPNs. It intercepts traffic at the kernel level via a WFP driver, routes it through Microsoft's cloud edge, and delivers it to on-premises resources via connectors. It enforces device compliance, conditional access, and per-app policies.

This research reverse-engineered the GSA wire protocol and built a fully independent tunnel client from scratch. The custom client runs on Linux and macOS, speaks the same gRPC-based protocol, and establishes a working ZTNA tunnel. Device posture checks are self-reported by the client and not validated server-side, which the custom client takes advantage of to present arbitrary device metadata.

## Components

### Rogue Client (`rogue-client/`)

A standalone Python tunnel client that connects to the GSA edge from **any OS** (Linux, macOS, Windows) and routes arbitrary traffic through the ZTNA tunnel. Uses a TUN interface for transparent network integration.

**Capabilities:**
- Establishes authenticated gRPC tunnel to Microsoft's edge servers
- Creates a TUN device and routes traffic through the tunnel transparently
- Per-flow authentication with automatic flow lifecycle management
- Spoofs device metadata to appear as a legitimate Windows client
- Parses JWT tokens from TokenBroker dump files by audience

See [`rogue-client/README.md`](rogue-client/README.md) for setup and usage.

### BOFs (`bofs/`)

Beacon Object Files for [BRC4](https://bruteratel.com/) (portable to Cobalt Strike with minor modifications).

#### GSA Token Theft (`bofs/gsa-token-theft/`)

Two BOFs for GSA-enrolled Windows targets:

| BOF | Description |
|-----|-------------|
| `gsa_enum` | Full GSA reconnaissance — installation, services, processes, registry, security posture, forwarding profile with JSON dump |
| `gsa_tbres_steal` | Extracts GSA authentication tokens from TokenBroker `.tbres` cache files via DPAPI decryption |

See [`bofs/README.md`](bofs/README.md) for build instructions.

### Protocol Definition (`proto/`)

The reconstructed ZTNA v2 protobuf definition, extracted from embedded descriptors in `GlobalSecureAccessTunnelingService.exe` via Ghidra analysis.

## Architecture

```
                              Rogue Client (any OS)
                                      |
                               gRPC / TLS :443
                                      |
                                      v
                     ┌────────────────────────────────┐
                     │     Microsoft GSA Edge          │
                     │  *.globalsecureaccess.microsoft │
                     │           .com                  │
                     └───────────────┬────────────────┘
                                     │
                          Outbound connector tunnel
                                     │
                                     v
                     ┌────────────────────────────────┐
                     │    On-Premises Connector         │
                     │    (customer network)            │
                     └───────────────┬────────────────┘
                                     │
                                     v
                           Internal Resources
                        (DCs, file shares, apps)
```

## Build & Usage

1. Build Protocol Buffers:
   ```bash
   cd proto
   python3 -m grpc_tools.protoc -I. --python_out=../rogue-client --grpc_python_out=../rogue-client gsa_tunnel.proto
   ```
2. Run the rogue client:
   ```bash
   cd rogue-client
   python3 gsa_tunnel.py --tenant <tenant-id> --tokens <path-to-tokens.json>
   ```

## Attack Flow

```
1. Land on GSA-enrolled Windows device
2. Run gsa_enum BOF → confirm GSA installation, dump forwarding profile
3. Run gsa_tbres_steal BOF → extract TUNNEL/PORTO/APS tokens from TokenBroker
4. Exfiltrate tokens to attacker machine
5. Run rogue client from attacker machine (Linux/macOS)
   → Full authenticated tunnel to internal network
   → Device posture spoofed, no compliance checks
   → Access persists until tokens expire (~75 min)
```

## License

This project is released for **authorized security testing and research purposes only**.

## ToDos
- [ ] Implement automatic token refresh in rogue client using refresh tokens
- [ ] Add Entra Internet Access (EIA) support

## Author

**Arshia Reisi** ([@_ar0x4](https://x.com/_ar0x4))
Presented at x33fcon 2026