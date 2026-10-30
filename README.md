
# Sahand Tunnel

A lightweight tunnel management system for Ubuntu servers.

## Installation

Run the following command on your Ubuntu server:

```bash
curl -fsSL https://raw.githubusercontent.com/sahand363/sahand-tunnel/main/install.sh | sudo bash
```

The installer will:

- Detect CPU architecture
- Download the precompiled binary from GitHub Releases
- Verify SHA256 checksum
- Install Sahand Tunnel
- Configure systemd
- Open the SSH management menu

## Supported Architectures

- Linux AMD64
- Linux ARM64

## Installation Roles

- Master
- Agent

## SSH Management

```bash
sahand-tunnel menu
```

## Service Management

```bash
systemctl status sahand-tunnel
systemctl restart sahand-tunnel
systemctl stop sahand-tunnel
```

## Update

```bash
sahand-tunnel-update
```

## Development

Builds and releases are handled by GitHub Actions.

No Go compiler is required on production servers.

## Project

https://github.com/sahand363/sahand-tunnel
