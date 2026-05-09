# TrunkPod

> **Disclaimer:** This is a Bachelor's degree project tested in a lab environment. If you deploy it in a real enterprise network, you take full responsibility for the outcome.

TrunkPod deploys honeypots across multiple VLANs to lure and expose attackers on compromised machines, giving you visibility into anomalies across all network segments.

---

## Installation

Clone the repository:
```bash
git clone https://github.com/kuzlik340/TrunkPod
```

Dependencies are installed automatically on first run via `install_requirements.sh`.

---
## Configuration

All configuration lives in the `configs/` directory:
```bash
cd configs/
```

You need to create two files. Example templates are provided to get you started:

|File|Template|
|---|---|
|`honeypots.yaml`|`honeypots.example.yaml`|
|`network.yaml`|`network.example.yaml`|

---
### Honeypots configuration
`configs/honeypots.yaml`
```yaml
honeypots:
  - name: honeypot1
    ip: 192.168.20.60
    vlan: 20
    services:
      - name: ldap
        port: 389
      - name: ssh
        port: 22
    mac: B8:2A:72:EF:00:01

  - name: honeypot2
    ip: 192.168.30.70
    vlan: 30
    services:
      - name: ldap
        port: 389
      - name: ssh
        port: 22
      - name: http_server
        port: 80
      - name: https_server
        port: 443
      - name: telnet
        port: 23
    mac: B8:2A:72:EF:00:02
```

**Field reference:**
- `name` — used as the Podman container name; must be unique across all honeypots.
- `ip` — must be unique. The script checks the target VLAN for conflicts before deploying; if the IP is taken, it will stop and ask you to change it.
- `vlan` — the VLAN ID where this honeypot will be deployed.
- `services` — list of services to run on this honeypot. Available options: `ssh`, `ldap`, `http_server`, `https_server`, `telnet`. The same service can run on multiple ports on the same honeypot, as long as ports don't conflict.
- `mac` — must be unique across all honeypots.

> A configuration validator runs before each deployment. If anything is misconfigured, it will tell you exactly what to fix.

---

### Network configuration
`configs/network.yaml`
```yaml
vlans:
  - id: 20
    name: network1
    range: 192.168.20.0/24
    gateway: 192.168.20.1

  - id: 30
    name: network2
    range: 192.168.30.0/24
    gateway: 192.168.30.1
```

**Field reference:**
- `id` — VLAN ID (must match the IDs used in `honeypots.yaml`).
- `name` — human-readable label, not used by scripts.
- `range` — IP range of the VLAN segment.
- `gateway` — gateway address for honeypots in this VLAN.

---

### BPF filter

After creating both config files, generate the BPF filter for the traffic parser:
```bash
python configs/create_filter_bpf.py configs/honeypots.yaml
```

Example output:
```
#define BPF_FILTER \
"(ether dst B8:2A:72:EF:00:01) or " \
"(ether dst B8:2A:72:EF:00:02) or " \
"(ip and (dst host 192.168.20.60 or dst host 192.168.30.70)) or " \
"(arp and (host 192.168.20.60 or host 192.168.30.70))"
```

Paste the output into `logging/low_level_logging/traffic_parser.c`, then build:
```bash
make
```

---

### Filebeat configuration

Edit `logging/logging_pipeline/.env` with your Elasticsearch connection details:
```env
STACK_VERSION=8.15.2
TRUNKPOD_LOG_PATH=/var/log/trunkpod
TRAFFIC_LOG_PATH=/var/log/traffic_parser
ELASTICHOST=https://<ip_address>
ELASTICUSER=elastic_user
ELASTICPASS=elastic_password
```

---
## Deployment

Run the deployment script, specifying the trunk interface:
```bash
sudo ./TrunkPod.sh --interface <your_interface>
```

This will:
1. Install any missing requirements
2. Validate your configuration
3. Prompt you to generate honeytokens (you choose how many)
4. Create all corresponding interfaces
5. Check if the IP addresses in configuration are available
6. Setup all networking for the honeypots
7. Deploy all honeypots defined in `honeypots.yaml`

---

## Logging

### Low-level traffic logs

The `traffic_parser` binary captures packets destined for your honeypots. It's best run as a systemd service:
```bash
cd logging/low_level_logging

sudo cp traffic_parser /usr/local/bin/
sudo cp traffic-parser.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable traffic_parser.service
sudo systemctl start traffic_parser.service
```

Check its status:
```bash
sudo systemctl status traffic_parser.service
```

### TrunkPod logs

Start the logging pipeline (Filebeat + forwarding to Elasticsearch):
```bash
cd logging/logging_pipeline
docker compose up
```