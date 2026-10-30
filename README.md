
# Sahand Tunnel

A modular tunnel management system for connecting multiple servers.

## Features

- Master and Agent installation roles
- Web-based management panel
- Independent server identity
- Automatic connection discovery (planned)
- Multiple TCP and UDP transport methods (planned)
- Automatic configuration synchronization (planned)
- Inbound port forwarding (planned)
- Local server analytics (planned)

## Technology

- Go
- Linux / Ubuntu
- HTTP API
- Web Dashboard

## Development

### Install Go

Install Go 1.22 or newer.

### Build

```bash
go build -o sahand-tunnel ./cmd/sahand-tunnel
```

### Initialize Master

```bash
./sahand-tunnel init --role master
```

### Initialize Agent

```bash
./sahand-tunnel init --role agent
```

### Start

```bash
./sahand-tunnel serve
```

Default panel address:

http://127.0.0.1:8080

## License

To be determined.
