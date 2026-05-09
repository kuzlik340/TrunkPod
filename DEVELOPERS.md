# Developer manual

## Project structure
```
├── README.md                        <- Project documentation and user manual
├── TrunkPod.sh                      <- Main script that orchestrates all others
├── assets                           <- CLI visual assets
│   ├── logos
│   │   ├── logo1.txt
│   │   ├── logo2.txt
│   │   ├── logo3.txt
│   │   ├── logo4.txt
│   │   ├── logo5.txt
│   │   ├── logo6.txt
│   │   ├── logo7.txt
│   │   ├── logo8.txt
│   │   ├── logo9.txt
│   │   └── logo10.txt
│   └── quotes.txt
├── build_services                   <- Builds and layers services onto the honeypot image
│   ├── base_functions.sh            <- Shared helpers used across all build scripts
│   ├── build_base.sh                <- Builds the shared base image
│   ├── build_http_server.sh         <- Layers HTTP service
│   ├── build_https_server.sh        <- Layers HTTPS service
│   ├── build_ldap.sh                <- Layers LDAP service
│   ├── build_ssh.sh                 <- Layers SSH service
│   ├── build_telnet.sh              <- Layers Telnet service
│   ├── finish.sh                    <- Finalizes the honeypot image build
│   ├── log_file_create.sh           <- Sets up the build-stage log file
│   ├── python_scripts               <- Decoy service implementations
│   │   ├── honeytokens.py           <- Shared honeytoken credential validation
│   │   ├── http_server.py
│   │   ├── https_server.py
│   │   ├── json_formatter.py        <- Shared JSON logging helper
│   │   ├── ldap.py
│   │   ├── ssh.py
│   │   └── telnet.py
│   ├── start.sh                     <- Kicks off the honeypot image build
│   ├── supervisor_configs           <- Supervisor configs for managing services
│   │   ├── supervisor_templates     <- Per-service templates consumed by build scripts
│   │   │   ├── http_server.conf
│   │   │   ├── https_server.conf
│   │   │   ├── ldap.conf
│   │   │   ├── ssh.conf
│   │   │   └── telnet.conf
│   │   └── supervisord.conf         <- Root supervisor config (PID 1)
│   └── template.sh                  <- Developer template for adding a new decoy service
├── check_changes.sh                 <- Detects changed files to resume deployment from the right stage
├── configs                          <- User-facing configuration directory
│   ├── create_filter_bpf.py         <- Generates BPF filter for the traffic parser
│   ├── honeypots.example.yaml       <- Honeypot config example
│   └── network.example.yaml         <- Network config example
├── generate_honeytokens.sh          <- Generates honeytoken credentials
├── global_functions.sh              <- Global shared functions
├── honeypots_config_checker.py      <- Validates honeypot config before deployment
├── install_requirements.sh          <- Installs all required dependencies
├── ip_checker.sh                    <- Checks for IP conflicts in target VLANs
├── logging
│   ├── logging_pipeline
│   │   ├── docker-compose.yml       <- Spins up Filebeat pipeline
│   │   └── filebeat.yml             <- Filebeat config for log forwarding
│   └── low_level_logging
│       ├── Makefile
│       ├── traffic-parser.service   <- Systemd unit for the traffic parser
│       └── traffic_parser.c         <- Packet capture daemon
├── run_honeypot.sh                  <- Starts honeypot containers
├── set_project_root.sh              <- Resolves and exports the project root path
├── setup_interfaces.sh              <- Configures VLAN interfaces on the host
└── setup_pods.sh                    <- Creates and wires up Podman pods
```


## Adding New Services
### How the build system works
Honeypot images have no `Dockerfile`. Instead, they are built dynamically at runtime using **Buildah**, which lets the scripts include only the services each honeypot actually needs. All honeypots share a common Debian base image defined in `build_services/build_base.sh`.

> If a service requires a large download (e.g. a third-party tool), add this tool(not service) to the base image so it is shared across all honeypots rather than downloaded per-image.

---
### 1. Create the service script
Add your service to `build_services/python_scripts/`. Stick to Python unless you have a strong reason not to — other languages require a separate directory and add complexity.

Name the file after the service exactly as it will appear in `honeypots.yaml`:
```
ssh   → ssh.py
ldap  → ldap.py
```

Use the shared helpers already available:
- `honeytokens.py` — validates credentials against honeytokens
- `json_formatter.py` — structured JSON logging

---
### 2. Add a Supervisor config
Create a config in `build_services/supervisor_configs/supervisor_templates/` using the same name:
```
ssh   → ssh.conf
ldap  → ldap.conf
```
This tells Supervisor how to run your service inside the container.

---
### 3. Create a build script
Create `build_services/build_<service_name>.sh`. Use `build_services/template.sh` as a starting point — it has the expected structure and comments to guide you.

Same naming convention applies:
```
ssh   → build_ssh.sh
ldap  → build_ldap.sh
```

---
### Checklist

- [ ] `build_services/python_scripts/<service>.py`
- [ ] `build_services/supervisor_configs/supervisor_templates/<service>.conf`
- [ ] `build_services/build_<service>.sh`