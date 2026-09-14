# Ria's SIEM

A basic Security Information and Event Management (SIEM) Proof of Concept built in Python.

> **Disclaimer**: This is a basic POC for educational purposes. Not intended for production use.

## Overview

Ria's SIEM is a lightweight SIEM solution that demonstrates the core concepts of security event monitoring:

- **Agent**: Deployed on Windows devices to collect Windows Event Logs
- **Server**: Receives, stores, and indexes logs from agents
- **Web Interface**: Query and visualise collected security events

## Screenshots

<img width="2543" height="1065" alt="Dashboard" src="https://github.com/user-attachments/assets/59ad6ca6-4196-4b3d-96b4-46959916afb1" />
<img width="2140" height="647" alt="Agent   Server" src="https://github.com/user-attachments/assets/c8872853-ebb2-491a-9c96-71587fac3dc7" />


## Architecture

```
┌─────────────────┐     HTTP/JSON      ┌─────────────────┐
│   Windows PC    │ ─────────────────► │     Server      │
│     (Agent)     │                    │   (Flask API)   │
└─────────────────┘                    └────────┬────────┘
                                                │
┌─────────────────┐     HTTP/JSON      ┌────────▼────────┐
│   Windows PC    │ ─────────────────► │    SQLite DB    │
│     (Agent)     │                    │   (logs.db)     │
└─────────────────┘                    └────────┬────────┘
                                                │
                                       ┌────────▼────────┐
                                       │  Web Interface  │
                                       │  (Flask + HTML) │
                                       └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)
- Windows (for agent) / Any OS (for server)
- Administrator privileges (for Security log access)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/rias-siem.git
   cd rias-siem
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Running the Server

```bash
cd server
python server.py
```

The server will start on `http://0.0.0.0:5000`

### Running the Agent (Windows)

**Important**: Run as Administrator to collect Security logs.

```bash
cd agent
python agent.py --server http://YOUR_SERVER_IP:5000
```

### Accessing the Web Interface

Open your browser and navigate to: `http://localhost:5000`

## Project Structure

```
rias-siem/
├── README.md
├── requirements.txt
├── server/
│   └── server.py
├── agent/
│   └── agent.py
└── web/
    └── templates/
        └── index.html
```

## Configuration

### Agent Configuration

| Argument | Description | Default |
|----------|-------------|---------|
| `--server` | Server URL | `http://localhost:5000` |
| `--interval` | Collection interval (seconds) | `30` |
| `--no-existing` | Skip historical logs | `false` |

The agent automatically collects from all log types: Security, System, and Application.

Example:
```bash
python agent.py --server http://192.168.1.100:5000 --interval 60
```

### Server Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SIEM_PORT` | Server port | `5000` |
| `SIEM_HOST` | Server host | `0.0.0.0` |
| `SIEM_DB_PATH` | Database path | `./logs.db` |

## Querying Logs

The web interface supports various query options:

- **By Source Host**: Filter logs from specific machines
- **By Event ID**: Search for specific Windows Event IDs
- **By Log Type**: Filter by Security, System, or Application
- **By Severity**: Filter by event severity level
- **By Time Range**: Specify start and end timestamps
- **By Keyword**: Full-text search in event messages

### Query Examples

1. **Find failed login attempts**:
   - Event ID: `4625`
   - Log Type: `Security`

2. **Find system errors from a specific host**:
   - Source Host: `WORKSTATION-01`
   - Log Type: `System`
   - Severity: `Error`

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/api/logs` | POST | Submit logs from agent |
| `/api/logs` | GET | Query logs with filters |
| `/api/stats` | GET | Get dashboard statistics |
| `/api/hosts` | GET | List registered hosts |

### Example API Usage

**Submit logs (Agent)**:
```bash
curl -X POST http://localhost:5000/api/logs \
  -H "Content-Type: application/json" \
  -d '{"host": "PC-01", "logs": [...]}'
```

**Query logs**:
```bash
curl "http://localhost:5000/api/logs?event_id=4625&log_type=Security"
```

## Security Considerations

This POC does **NOT** include:

- Authentication/Authorisation
- TLS/SSL encryption
- Input validation hardening
- Rate limiting
- Log integrity verification

**For production use**, you should implement all of the above.

## Windows Event IDs Reference

Common security-relevant Event IDs:

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credential logon |
| 4672 | Special privileges assigned |
| 4688 | New process created |
| 4720 | User account created |
| 4726 | User account deleted |
| 7045 | Service installed |

## Contributing

This is a POC project, but contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Licence

MIT Licence - See [LICENCE](LICENCE) for details.

## Author

**Ria**
