# json_formatter.py

import logging
import json

class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON for easy ingestion."""

    def __init__(self, dst_ip: str, dst_port: int, service: str):
        super().__init__()
        self.dst_ip   = dst_ip
        self.dst_port = dst_port
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        from datetime import datetime, timezone
        log_record = {
            "timestamp" : datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level"     : record.levelname,
            "logger"    : record.name,
            "service"   : "HoneyBridge",
            "component" : self.service,
            "message"   : record.getMessage(),
            "dst_ip_addr": self.dst_ip,
            "dst_port"  : self.dst_port,
        }
        if hasattr(record, "src_ip_addr"):
            log_record["src_ip_addr"] = record.src_ip_addr
        if hasattr(record, "src_port"):
            log_record["src_port"] = record.src_port
        if hasattr(record, "path"): # used for http
            log_record["path"] = record.path

        return json.dumps(log_record)
