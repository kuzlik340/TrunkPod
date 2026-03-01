"""
RDP Honeypot - Complete FreeRDP-based implementation
Fully reimplemented with FreeRDP protocol reference and detailed debug logging

Protocol phases:
1. X.224 Connection Negotiation (Connection Request/Confirm)
2. MCS Connection Sequence (Connect-Initial/Connect-Response)
3. MCS Channel Establishment (ErectDomain/AttachUser/ChannelJoin)
4. RDP Session Establishment (Security/License/Capability)
5. User Authentication Capture

FIXES applied vs original:
- Removed duplicate _build_gcc_conference_create_response (Python used wrong one)
- Fixed GCC T.124 wrapping: now uses correct OID + H221NonStandard "Duca" key
- Fixed _encode_ber_length: always returns bytes (was mixing bytes/bytearray)
- Fixed MCS Connect-Response userData structure that nmap rdp.lua expects
"""

import socket
import threading
import struct
import logging
import time
import datetime
import os
import sys
from io import BytesIO

try:
    from json_formatter import JSONFormatter
    HAS_JSON_FORMATTER = True
except ImportError:
    HAS_JSON_FORMATTER = False


def build_logger(name: str, log_file: str, dst_ip: str, dst_port: int) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.FileHandler(log_file, mode="a")
    if HAS_JSON_FORMATTER:
        handler.setFormatter(JSONFormatter(dst_ip, dst_port, "RDP"))
    logger.addHandler(handler)

    return logger


class RDPProtocolFreeRDP:
    """
    FreeRDP-based RDP protocol handler
    Reference: https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/core/
    """

    # X.224 Protocol Constants
    X224_TPDU_CONNECTION_REQUEST = 0xE0
    X224_TPDU_CONNECTION_CONFIRM = 0xD0
    X224_TPDU_DATA = 0xF0

    # MCS Protocol Constants
    MCS_CONNECT_INITIAL = 0x65
    MCS_CONNECT_RESPONSE = 0x66
    MCS_ERECT_DOMAIN_REQUEST = 0x04
    MCS_ATTACH_USER_REQUEST = 0x28
    MCS_ATTACH_USER_CONFIRM = 0x2E
    MCS_CHANNEL_JOIN_REQUEST = 0x38
    MCS_CHANNEL_JOIN_CONFIRM = 0x3E
    MCS_SEND_DATA_REQUEST = 0x64
    MCS_SEND_DATA_INDICATION = 0x68

    # Protocol Negotiation Flags
    PROTOCOL_RDP = 0x00000000
    PROTOCOL_SSL = 0x00000001
    PROTOCOL_HYBRID = 0x00000002
    PROTOCOL_RDSTLS = 0x00000004
    PROTOCOL_HYBRID_EX = 0x00000008

    # RDP Protocol Constants
    RDP_NEG_REQ = 0x01
    RDP_NEG_RSP = 0x02
    RDP_NEG_FAILURE = 0x03

    # Server Data Block Types
    SC_CORE = 0x0C01
    SC_SECURITY = 0x0C02
    SC_NET = 0x0C03

    def __init__(self, client_socket, client_addr, logger):
        self.client_socket = client_socket
        self.client_addr = client_addr
        self.logger = logger

        self.phase = 0
        self.client_requested_protocols = 0
        self.selected_protocol = self.PROTOCOL_RDP
        self.user_id = 0x03EA + 1   # MCS User ID (1002)
        self.channel_id = 0x03EB    # MCS Channel ID (1003)

        self.debug = True
        self.verbose_ber = True

        self.connection_established = False
        self.credentials_captured = []

    # -------------------------------------------------------------------------
    # Logging helpers
    # -------------------------------------------------------------------------

    def log_debug(self, message, data=None):
        if self.debug:
            if data is not None:
                if isinstance(data, (bytes, bytearray)):
                    hex_str = ' '.join(f'{b:02x}' for b in data[:64])
                    if len(data) > 64:
                        hex_str += f'... ({len(data)} bytes total)'
                    self.logger.info(f"[DEBUG] {message}: {hex_str}")
                else:
                    self.logger.info(f"[DEBUG] {message}: {data}")
            else:
                self.logger.info(f"[DEBUG] {message}")

    def log_phase(self, phase, message):
        self.logger.info(f"[PHASE-{phase}] {message}")
        try:
            logger.warning(f"[PHASE-{phase}] {message}", extra={
                "src_ip_addr": self.client_addr[0],
                "src_port": self.client_addr[1],
            })
        except Exception:
            pass

    def log_ber(self, message, data):
        if self.verbose_ber and data:
            hex_str = ' '.join(f'{b:02x}' for b in data[:32])
            self.logger.info(f"[BER] {message}: {hex_str}")

    # -------------------------------------------------------------------------
    # BER encoding helpers
    # FIX: _encode_ber_length now *always* returns bytes (was returning bytearray
    #      in the long form), which caused nmap's Lua string.unpack to receive a
    #      boolean instead of a string and crash with the reported traceback.
    # -------------------------------------------------------------------------

    def _encode_ber_length(self, length):
        """Encode BER definite length. Always returns bytes."""
        if length < 0x80:
            # Short form: single byte
            return bytes([length])
        else:
            # Long form: 0x80|n followed by n bytes (big-endian)
            length_bytes = []
            temp = length
            while temp > 0:
                length_bytes.insert(0, temp & 0xFF)
                temp >>= 8
            return bytes([0x80 | len(length_bytes)] + length_bytes)

    def _parse_ber_length(self, data, offset):
        """Parse BER length encoding — returns (length, new_offset)."""
        if offset >= len(data):
            return 0, offset

        first_byte = data[offset]
        offset += 1

        if first_byte & 0x80 == 0:
            return first_byte, offset
        else:
            num_length_bytes = first_byte & 0x7F
            if num_length_bytes == 0:
                return 0, offset  # indefinite form — treat as 0
            if offset + num_length_bytes > len(data):
                return 0, offset
            length = 0
            for i in range(num_length_bytes):
                length = (length << 8) | data[offset + i]
            offset += num_length_bytes
            return length, offset

    # -------------------------------------------------------------------------
    # Phase 1 — X.224 Connection Negotiation
    # -------------------------------------------------------------------------

    def handle_connection(self):
        try:
            self.log_phase(0, f"Starting to handle from {self.client_addr} RDP connection")

            if not self._phase1_x224_connection():
                self.log_phase(1, "X.224 connection negotiation failed")
                return False

            if not self._phase2_mcs_connection():
                self.log_phase(2, "MCS connection establishment failed")
                return False

            if not self._phase3_mcs_channels():
                self.log_phase(3, "MCS channel establishment failed")
                return False

            if not self._phase4_rdp_negotiation():
                self.log_phase(4, "RDP session negotiation failed")
                return False

            self._phase5_authentication_session()
            return True

        except Exception as e:
            self.logger.error(f"Connection handling exception: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
        finally:
            self._cleanup()

    def _phase1_x224_connection(self):
        self.log_phase(1, "Starting X.224 connection negotiation")
        try:
            data = self.client_socket.recv(1024)
            if not data:
                return False

            self.log_debug("Received X.224 connection request", data)

            if len(data) < 4:
                return False

            tpkt_version = data[0]
            tpkt_length = struct.unpack('>H', data[2:4])[0]
            self.log_debug(f"TPKT: version={tpkt_version}, length={tpkt_length}")

            if tpkt_version != 3:
                return False

            if len(data) < 10:
                return False

            x224_length = data[4]
            x224_type = data[5]
            self.log_debug(f"X.224: LI={x224_length}, type=0x{x224_type:02x}")

            if x224_type != self.X224_TPDU_CONNECTION_REQUEST:
                self.log_debug(f"Not an X.224 CR: 0x{x224_type:02x}")
                return False

            # Optional negotiation request after X.224 header
            x224_total_length = 4 + 1 + x224_length
            if len(data) > x224_total_length:
                nego_data = data[x224_total_length:]
                if nego_data:
                    self.log_debug("Negotiation request data", nego_data)
                    self._parse_rdp_nego_req(nego_data)

            response = self._build_x224_connection_confirm()
            self.client_socket.send(response)
            self.log_debug("Sent X.224 connection confirm", response)

            self.log_phase(1, "X.224 connection negotiation complete")
            return True

        except Exception as e:
            self.log_phase(1, f"X.224 negotiation exception: {e}")
            return False

    def _parse_rdp_nego_req(self, data):
        if len(data) < 8:
            return
        nego_type = data[0]
        self.client_requested_protocols = struct.unpack('<I', data[4:8])[0]
        self.log_debug(f"Client requested protocols: 0x{self.client_requested_protocols:08x}")

        if nego_type == self.RDP_NEG_REQ:
            self.selected_protocol = self.PROTOCOL_RDP
            self.log_debug("Selected standard RDP protocol (no encryption)")

    def _build_x224_connection_confirm(self):
        x224_data = bytearray()
        x224_data.append(self.X224_TPDU_CONNECTION_CONFIRM)
        x224_data.extend([0x00, 0x00])  # dst-ref
        x224_data.extend([0x00, 0x00])  # src-ref
        x224_data.append(0x00)          # class option

        # Always include RDP_NEG_RSP so Windows MSTSC knows we selected protocol=0.
        # If we omit it when client_requested_protocols==0, some clients disconnect.
        # We always select PROTOCOL_RDP (0) — no TLS, no CredSSP — which is correct
        # for a honeypot that captures plaintext credentials.
        nego_resp = bytearray()
        nego_resp.append(self.RDP_NEG_RSP)
        nego_resp.append(0x00)                          # flags: none
        nego_resp.extend(struct.pack('<H', 8))           # length = 8
        nego_resp.extend(struct.pack('<I', self.PROTOCOL_RDP))  # selected = 0
        x224_data.extend(nego_resp)

        x224_header = bytearray([len(x224_data)]) + x224_data
        total_length = 4 + len(x224_header)
        tpkt = bytearray([0x03, 0x00]) + bytearray(struct.pack('>H', total_length))
        return bytes(tpkt + x224_header)

    # -------------------------------------------------------------------------
    # Phase 2 — MCS Connection (Connect-Initial / Connect-Response)
    # -------------------------------------------------------------------------

    def _recv_tpkt(self):
        """
        Read exactly one complete TPKT packet from the socket.

        TPKT header (RFC 2126) is always 4 bytes:
          [version=3][reserved=0][length_hi][length_lo]
        where length is the TOTAL packet size including the 4-byte header.

        Windows MSTSC sends large MCS Connect-Initial packets (~420 bytes) that
        may arrive in multiple TCP segments. A single recv() would return only the
        first fragment, causing phase 2 to fail. This method reassembles correctly.
        """
        header = b""
        while len(header) < 4:
            chunk = self.client_socket.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk

        total_length = struct.unpack(">H", header[2:4])[0]
        remaining = total_length - 4

        body = b""
        while len(body) < remaining:
            chunk = self.client_socket.recv(remaining - len(body))
            if not chunk:
                return None
            body += chunk

        return header + body

    def _phase2_mcs_connection(self):
        self.log_phase(2, "Starting MCS connection establishment")
        try:
            # _recv_tpkt handles TCP fragmentation from Windows MSTSC
            data = self._recv_tpkt()
            if not data:
                self.log_debug("No data received for MCS Connect-Initial")
                return False

            self.log_debug("Received MCS Connect-Initial", data)

            if len(data) < 8:
                return False

            mcs_data = data[7:]   # Skip TPKT(4) + X.224 Data PDU header(3)
            self.log_debug("MCS data portion", mcs_data)

            if not self._parse_mcs_connect_initial(mcs_data):
                self.log_debug("MCS Connect-Initial parsing failed")
                return False

            response = self._build_mcs_connect_response()
            self.client_socket.send(response)
            self.log_debug("Sent MCS Connect-Response", response)

            self.log_phase(2, "MCS connection establishment complete")
            return True

        except Exception as e:
            import traceback
            self.log_phase(2, f"MCS connection exception: {e}")
            self.logger.error(traceback.format_exc())
            return False

    def _parse_mcs_connect_initial(self, data):
        """
        Parse MCS Connect-Initial tag and length.

        Windows MSTSC sends APPLICATION 101 as a 2-byte long-form BER tag:
          0x7f 0x65 [BER-length] [content...]
        The original code called _parse_ber_length(data, 1), which read data[1]=0x65
        as the BER length byte (short form, value=101) — treating the second tag
        byte as a length. The content-start offset was then wrong by 3 bytes,
        making the parse appear to succeed but producing garbage offsets that
        caused the MCS Connect-Response to be based on misread data.

        Fix: when the first byte is 0x7f (long-form tag indicator), skip BOTH
        tag bytes (0x7f and 0x65) before reading the BER length at index 2.
        """
        try:
            if len(data) < 3:
                return False

            first_byte = data[0]
            if first_byte == self.MCS_CONNECT_INITIAL:
                # Short-form APPLICATION 101 tag (0x65) — length at index 1
                ber_length_offset = 1
                self.log_ber("MCS Connect-Initial (short tag 0x65)", data[:1])
            elif first_byte == 0x7f and len(data) > 2:
                # Long-form 2-byte tag: 0x7f 0x65 — length at index 2
                second_byte = data[1]
                self.log_ber(f"MCS Connect-Initial (long tag 0x7f 0x{second_byte:02x})", data[:2])
                ber_length_offset = 2
            else:
                self.log_debug(f"Unexpected MCS Connect-Initial tag: 0x{first_byte:02x}")
                return False

            length, content_offset = self._parse_ber_length(data, ber_length_offset)
            self.log_debug(f"MCS Connect-Initial: BER length={length}, content at offset {content_offset}")
            self.log_ber("Connect-Initial content start", data[content_offset:content_offset + 16])
            return True

        except Exception as e:
            self.log_debug(f"MCS Connect-Initial parse exception: {e}")
            return False

    def _build_mcs_connect_response(self):
        """
        Build a standards-compliant MCS Connect-Response (T.125 APPLICATION 102).

        FIX — the critical change vs the original:
        The userData OCTET STRING must carry a proper GCC T.124
        ConferenceCreateResponse wrapped with the correct OID and H.221
        non-standard key "Duca" (0x44756361). Without this wrapping, nmap's
        rdp.lua hits the OID/length decode path and crashes with the reported
        "bad argument #2 to 'unpack'" error because it receives a boolean
        (failed read) instead of a string.
        """

        # 1. Result: rt-successful (0) — ENUMERATED
        result = bytes([0x0A, 0x01, 0x00])

        # 2. Called Connect Id — INTEGER 121 (0x79)
        called_id = bytes([0x02, 0x01, 0x79])

        # 3. Domain Parameters — SEQUENCE (ITU-T T.125)
        domain_params = bytes([
            0x30, 0x19,
            0x02, 0x01, 0x22,       # maxChannelIds:  34
            0x02, 0x01, 0x03,       # maxUserIds:  3
            0x02, 0x01, 0x00,       # maxTokenIds:  0
            0x02, 0x01, 0x01,       # numPriorities:  1
            0x02, 0x01, 0x00,       # minThroughput:  0
            0x02, 0x01, 0x01,       # maxHeight:  1
            0x02, 0x02, 0xFF, 0xF8, # maxMCSPDUsize:  65528
            0x02, 0x01, 0x02,       # protocolVersion:  2
        ])

        # 4. userData — OCTET STRING wrapping the GCC response
        gcc_response = self._build_gcc_conference_create_response()
        user_data = bytes([0x04]) + self._encode_ber_length(len(gcc_response)) + gcc_response

        content = result + called_id + domain_params + user_data

        # APPLICATION 102 tag + BER length.
        #
        # CRITICAL: nmap's rdp.lua ConfCreateResponse.parse() hardcodes:
        #   _, pos = decoder.decodeLength(data, 3)
        # decodeLength reads the byte at Lua-pos-3 = Python-index-2.
        # For the parse to work, Python index 2 MUST be 0x82 (BER long-form,
        # 2-byte length), so that decodeLength correctly skips the header and
        # lands pos at content[0] = 0x0a (ENUMERATED result tag).
        #
        # Layout required:  [tag0][tag1][0x82][HH][LL][0x0a content...]
        #                    idx0   idx1  idx2  idx3 idx4  idx5=content[0]
        #
        # This means we need a 2-byte tag prefix: 0x7f 0x66 (long-form BER tag
        # for APPLICATION 102, same convention nmap uses for APPLICATION 101:
        # 0x7f 0x65). With the 2-byte tag, the BER length starts at index 2
        # and 0x82 is always valid since our content fits in 2 length bytes.
        n = len(content)
        mcs_response = bytes([0x7f, 0x66, 0x82, (n >> 8) & 0xFF, n & 0xFF]) + content

        self.log_debug(f"MCS Connect-Response total length: {len(mcs_response)}")
        return self._wrap_x224_data(mcs_response)

    def _build_gcc_conference_create_response(self):
        """
        Build the GCC T.124 ConferenceCreateResponse userData blob.

        nmap's rdp.lua hardcodes offset 22 (Lua 1-indexed) to call
        decodeLength(), expecting to land exactly at the BER-encoded length of
        the server data blocks.  The layout that satisfies this is:

          Byte  0- 1: 00 05          T.124 object length = 5
          Byte  2- 6: 00 14 7c 00 01 T.124 OID 0.0.20.124.0.1
          Byte  7- 8: 81 NN          connectPDU BER length — FORCED 2-byte
                                     (even if value < 128) so that offsets 9+
                                     land on the GCC header correctly
          Byte  9-16: GCC ConferenceCreateResponse PER header (8 bytes)
          Byte 17-20: 44 75 63 61    H.221 key "Duca"
          Byte    21: NN             server data BER length  ← Lua offset 22
          Byte 22+  : SC_CORE / SC_SECURITY / SC_NET blocks

        This is the ONLY layout where nmap's hardcoded offset lands correctly.
        """
        server_data_blocks = self._build_server_data_blocks()

        # T.124 ConnectData header — exactly 7 bytes, non-negotiable
        t124_header = bytes([
            0x00, 0x05,              # object length = 5
            0x00, 0x14, 0x7c, 0x00, 0x01,  # OID 0.0.20.124.0.1
        ])

        # GCC ConferenceCreateResponse PER header — exactly 8 bytes
        gcc_header = bytes([0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00])

        # H.221 non-standard key "Duca" (Microsoft RDP) — exactly 4 bytes
        h221_key = b'Duca'

        # Server data BER length — 1 byte (32 bytes < 128)
        server_data_ber_len = bytes([len(server_data_blocks)])

        # connectPDU = gcc_header + h221_key + server_data_ber_len + server_data
        connect_pdu = gcc_header + h221_key + server_data_ber_len + server_data_blocks

        # CRITICAL: force 2-byte BER (0x81 NN) for connectPDU length.
        # This keeps the byte count to exactly 21 bytes before server_data_ber_len,
        # which puts it at Lua offset 22 where nmap calls decodeLength().
        # Using a 1-byte BER here shifts everything left by 1 and breaks nmap.
        connect_pdu_ber_len = bytes([0x81, len(connect_pdu)])

        user_data = t124_header + connect_pdu_ber_len + connect_pdu

        self.log_debug(f"GCC ConferenceCreateResponse length: {len(user_data)}")
        self.log_debug(f"userData[21] (nmap offset 22) = 0x{user_data[21]:02x} "
                       f"(server data BER len = {len(server_data_blocks)})")
        return user_data

    def _build_server_data_blocks(self):
        """Build SC_CORE + SC_SECURITY + SC_NET data blocks."""
        return (self._build_server_core_data() +
                self._build_server_security_data() +
                self._build_server_network_data())

    def _build_server_core_data(self):
        data = bytearray()
        data.extend(struct.pack('<H', self.SC_CORE))
        data.extend(struct.pack('<H', 12))              # length = 12
        data.extend(struct.pack('<I', 0x00080004))      # RDP 5.0 version
        data.extend(struct.pack('<I', self.client_requested_protocols))
        self.log_debug(f"SC_CORE length: {len(data)}")
        return bytes(data)

    def _build_server_security_data(self):
        data = bytearray()
        data.extend(struct.pack('<H', self.SC_SECURITY))
        data.extend(struct.pack('<H', 12))
        data.extend(struct.pack('<I', 0x00000000))      # ENCRYPTION_METHOD_NONE
        data.extend(struct.pack('<I', 0x00000000))      # ENCRYPTION_LEVEL_NONE
        self.log_debug(f"SC_SECURITY length: {len(data)}")
        return bytes(data)

    def _build_server_network_data(self):
        data = bytearray()
        data.extend(struct.pack('<H', self.SC_NET))
        data.extend(struct.pack('<H', 8))
        data.extend(struct.pack('<H', self.channel_id))
        data.extend(struct.pack('<H', 0x0000))          # 0 static channels
        self.log_debug(f"SC_NET length: {len(data)}")
        return bytes(data)

    # -------------------------------------------------------------------------
    # X.224 Data PDU wrapper
    # -------------------------------------------------------------------------

    def _wrap_x224_data(self, mcs_data):
        x224 = bytes([0x02, self.X224_TPDU_DATA, 0x80])   # LI=2, Data TPDU, EOT
        total_length = 4 + len(x224) + len(mcs_data)
        tpkt = bytes([0x03, 0x00]) + struct.pack('>H', total_length)
        return tpkt + x224 + mcs_data

    # -------------------------------------------------------------------------
    # Phase 3 — MCS Channel Establishment
    # -------------------------------------------------------------------------

    def _phase3_mcs_channels(self):
        """
        Handle the MCS channel setup sequence:
          Client → ErectDomainRequest   (no response)
          Client → AttachUserRequest    → AttachUserConfirm
          Client → ChannelJoinRequest×N → ChannelJoinConfirm×N

        Windows sends ErectDomain + AttachUser in the same TCP segment, then
        multiple ChannelJoinRequests. We use _recv_tpkt() for reliable reads
        and keep looping until we see a timeout (no more PDUs pending).
        """
        self.log_phase(3, "Starting MCS channel establishment")
        try:
            got_attach_confirm = False
            join_count = 0

            for _ in range(20):
                try:
                    self.client_socket.settimeout(3.0)
                    data = self._recv_tpkt()
                    if not data:
                        break

                    self.log_debug("Received MCS PDU", data)

                    # A single TPKT may contain multiple MCS PDUs concatenated.
                    # Parse them all out of the payload.
                    payload = data[7:]  # strip TPKT(4) + X224(3)
                    offset = 0
                    while offset < len(payload):
                        pdu_type = payload[offset]

                        if pdu_type == 0x04:
                            # ErectDomainRequest — variable length, safe to skip rest
                            self.log_debug("ErectDomainRequest — no response")
                            offset = len(payload)  # consume rest

                        elif (pdu_type & 0xFC) == 0x28:
                            # AttachUserRequest (2 bytes)
                            self.log_debug("AttachUserRequest → sending AttachUserConfirm")
                            self.client_socket.send(self._build_attach_user_confirm())
                            got_attach_confirm = True
                            offset += 2

                        elif (pdu_type & 0xFC) == 0x38:
                            # ChannelJoinRequest (5 bytes)
                            if offset + 4 < len(payload):
                                ch_id = struct.unpack('>H', payload[offset+3:offset+5])[0]
                            else:
                                ch_id = self.channel_id
                            self.log_debug(f"ChannelJoinRequest channel=0x{ch_id:04x} → confirm")
                            self.client_socket.send(self._build_channel_join_confirm_with_id(ch_id))
                            join_count += 1
                            offset += 5

                        elif pdu_type == 0x64:
                            # SendDataRequest — client already advancing to RDP phase
                            self.log_debug("SendDataRequest seen in Phase 3 — stopping channel loop")
                            # Put it back by handling in phase 4; we're done here
                            self._pending_pdu = data
                            offset = len(payload)

                        else:
                            self.log_debug(f"Unknown MCS PDU 0x{pdu_type:02x} — skipping rest")
                            offset = len(payload)

                except socket.timeout:
                    self.log_debug("Phase 3 timeout — no more channel PDUs")
                    break

            self.log_phase(3, f"MCS channels done: attach_confirm={got_attach_confirm}, joins={join_count}")
            return True

        except Exception as e:
            self.log_phase(3, f"MCS channel exception: {e}")
            return False

    def _build_attach_user_confirm(self):
        pdu = bytes([0x2E, 0x00,
                     (self.user_id >> 8) & 0xFF, self.user_id & 0xFF])
        self.log_debug(f"AttachUserConfirm user_id=0x{self.user_id:04x}")
        return self._wrap_x224_data(pdu)

    def _build_channel_join_confirm_with_id(self, ch_id):
        pdu = bytes([0x3F, 0x00,
                     (self.user_id >> 8) & 0xFF, self.user_id & 0xFF,
                     (ch_id >> 8) & 0xFF, ch_id & 0xFF])
        self.log_debug(f"ChannelJoinConfirm ch=0x{ch_id:04x}")
        return self._wrap_x224_data(pdu)

    def _build_channel_join_confirm(self):
        return self._build_channel_join_confirm_with_id(self.channel_id)

    # -------------------------------------------------------------------------
    # Phase 4 — RDP Security / License / Capabilities
    # -------------------------------------------------------------------------

    def _phase4_rdp_negotiation(self):
        """
        Complete the RDP session setup so Windows shows the login screen.

        Sequence (plain RDP, no encryption):
          recv: ClientSecurityExchange (optional, if encryption negotiated)
          recv: ClientInfo PDU  ← contains username + password + domain
          send: License Error PDU (STATUS_VALID_CLIENT — no license needed)
          send: Demand Active PDU (server capabilities)
          recv: Confirm Active PDU
          send: Synchronize + Control(cooperate) + Control(granted) + FontMap

        Without sending DemandActive and the post-sync PDUs, Windows shows
        error 0x2104 (ERRINFO_LICENSE_INTERNAL or protocol mismatch).
        """
        self.log_phase(4, "Starting RDP session negotiation")
        try:
            self.client_socket.settimeout(10.0)

            # ── Step 1: receive ClientInfo (and possibly SecurityExchange first) ──
            client_info_data = None
            for attempt in range(5):
                data = getattr(self, '_pending_pdu', None)
                self._pending_pdu = None
                if data is None:
                    try:
                        data = self._recv_tpkt()
                    except socket.timeout:
                        break
                if not data:
                    break

                self.log_debug(f"Phase4 recv attempt {attempt+1}", data)

                # Detect ClientInfo PDU: MCS SendDataRequest (0x64) wrapping
                # a ShareControlHeader PDU type 0x0013 (INFO_PKT) or just
                # look for the INFO_FLAG in the security header.
                # For plain RDP (no encryption), security header flags=0x0040 (INFO_PKT)
                # or the data will be > 100 bytes with username/password/domain.
                if len(data) >= 12 and data[7] == 0x64:
                    rdp_payload = data[11:]  # skip TPKT+X224+MCS header (vary)
                    # Try to parse as ClientInfo
                    creds = self._parse_client_info(data)
                    if creds:
                        self.log_phase(4, f"ClientInfo captured: {creds}")
                        self.credentials_captured.append({
                            'timestamp': datetime.datetime.now().isoformat(),
                            'client_addr': self.client_addr,
                            'credentials': creds,
                        })
                        self._save_credentials_dict(creds)
                        client_info_data = data
                        break
                    # May be SecurityExchange — keep reading
                    self.log_debug("Received SendDataRequest — not yet ClientInfo, continuing")

            # ── Step 2: send License Error PDU ───────────────────────────────
            lic_pdu = self._build_license_error_pdu()
            self.client_socket.send(lic_pdu)
            self.log_debug("Sent License Error PDU (STATUS_VALID_CLIENT)", lic_pdu)

            # ── Step 3: send Demand Active PDU ───────────────────────────────
            demand_pdu = self._build_demand_active_pdu()
            self.client_socket.send(demand_pdu)
            self.log_debug("Sent Demand Active PDU", demand_pdu)

            # ── Step 4: recv Confirm Active PDU ──────────────────────────────
            for _ in range(5):
                try:
                    data = self._recv_tpkt()
                    if not data:
                        break
                    self.log_debug("Phase4 post-demand recv", data)
                    # Confirm Active has PDUType 0x0013
                    if len(data) > 12:
                        # Check MCS SDR (0x64) containing ShareControl type 0x13
                        if data[7] == 0x64:
                            self.log_debug("Received client PDU after DemandActive")
                            break
                except socket.timeout:
                    break

            # ── Step 5: send Synchronize sequence ────────────────────────────
            for pdu in self._build_sync_sequence():
                self.client_socket.send(pdu)
            self.log_debug("Sent post-activation sync sequence")

            self.log_phase(4, "RDP session negotiation complete")
            self.connection_established = True
            return True

        except Exception as e:
            import traceback
            self.log_phase(4, f"RDP negotiation exception: {e}")
            self.logger.error(traceback.format_exc())
            return False

    # ── PDU builders for Phase 4 ─────────────────────────────────────────────

    def _mcs_send_data(self, rdp_data):
        """Wrap RDP data in MCS SendDataIndication"""
        pdu = bytearray([0x68])
        pdu.append((self.user_id >> 8) & 0xFF)
        pdu.append(self.user_id & 0xFF)
        pdu.append((self.channel_id >> 8) & 0xFF)
        pdu.append(self.channel_id & 0xFF)
        pdu.append(0x70)  # priority flags
        # Segmentation: single segment, high bit set
        pdu.append(0x80 | ((len(rdp_data) >> 8) & 0x7F))
        pdu.append(len(rdp_data) & 0xFF)
        pdu.extend(rdp_data)
        return self._wrap_x224_data(bytes(pdu))

    def _build_license_error_pdu(self):
        """
        Server License Error PDU — STATUS_VALID_CLIENT (0x00000007).
        Tells Windows no license check is needed and it can proceed.
        MS-RDPBCGR §2.2.1.12
        """
        # Security header: SEC_LICENSE_PKT = 0x0080
        sec_hdr = struct.pack('<HH', 0x0080, 0x0000)
        # License ERROR_ALERT message
        # bMsgType=0xFF, flags=0x02 (PREAMBLE_VERSION_3_0), wMsgSize=14
        # dwErrorCode=STATUS_VALID_CLIENT, dwStateTransition=ST_NO_TRANSITION
        # bbErrorInfo: wBlobType=BB_ERROR_BLOB(3), wBlobLen=0
        lic_msg = (bytes([0xFF, 0x02]) +
                   struct.pack('<H', 14) +
                   struct.pack('<II', 0x00000007, 0x00000002) +
                   struct.pack('<HH', 0x0003, 0x0000))
        return self._mcs_send_data(sec_hdr + lic_msg)

    def _build_demand_active_pdu(self):
        """
        Server Demand Active PDU — announces server capabilities.
        Client must respond with Confirm Active before the session proceeds.
        MS-RDPBCGR §2.2.1.13
        """
        SHARE_ID = 0x000103EA

        def cap(cap_type, data):
            return struct.pack('<HH', cap_type, 4 + len(data)) + data

        # General capability set (CAPSTYPE_GENERAL = 0x0001)
        general = cap(0x0001, struct.pack('<HHHHHHHHHBB',
            0x0001, 0x0003, 0x0200, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x00, 0x00))

        # Bitmap capability set (CAPSTYPE_BITMAP = 0x0002)
        bitmap = cap(0x0002, struct.pack('<HHHHHHHBBHH',
            24, 1, 1, 1,          # bpp, receive flags
            1280, 768, 0,         # width, height, pad
            1, 1,                  # desktopResizeFlag, bitmapCompressionFlag
            0x0000, 1) + b'\x00\x00')  # highColor+drawFlags, multiRect, pad

        # Order capability set (CAPSTYPE_ORDER = 0x0003) — 88 bytes total
        order_data = (b'\x00' * 16 +
                      struct.pack('<IHH', 0x40420F00, 1, 20) +
                      struct.pack('<HHH', 0, 1, 0) +
                      struct.pack('<I', 0) +
                      struct.pack('<H', 0x0022) +
                      b'\x00' * 32 +
                      struct.pack('<HHII', 0, 0, 0x000F4240, 0x000F4240))
        order = cap(0x0003, order_data[:84])

        caps = general + bitmap + order
        source_desc = b"RDP\x00"

        demand_body = (
            struct.pack('<I', SHARE_ID) +
            struct.pack('<H', len(source_desc)) +
            struct.pack('<H', 2 + 2 + len(caps)) +
            source_desc +
            struct.pack('<HH', 3, 0) +  # numberCapabilities, pad
            caps
        )

        # ShareControlHeader: totalLength | PDUTYPE_DEMANDACTIVEPDU(0x0011) | PDUSource
        total_len = 6 + len(demand_body)
        share_ctrl = struct.pack('<HHH', total_len, 0x0011, self.user_id & 0xFFFF)

        # No encryption → null security header
        rdp_data = struct.pack('<HH', 0, 0) + share_ctrl + demand_body
        return self._mcs_send_data(rdp_data)

    def _build_sync_sequence(self):
        """
        Post-activation synchronisation sequence the server must send after
        receiving ConfirmActive. Without these PDUs Windows disconnects.
        MS-RDPBCGR §1.3.1.1 (Connection Sequence)
        """
        SHARE_ID = 0x000103EA
        PDU_TYPE_DATA = 0x0017

        def rdp_data_pdu(pdutype2, share_data):
            inner = (struct.pack('<I', SHARE_ID) +
                     bytes([0x00, 0x01]) +           # pad1, streamId=STREAM_LOW
                     struct.pack('<H', 18 + len(share_data)) +  # uncompressedLength
                     bytes([pdutype2, 0x00]) +        # pduType2, generalCompressedType
                     struct.pack('<H', 0) +           # generalCompressedSize
                     share_data)
            total_len = 6 + len(inner)
            share_ctrl = struct.pack('<HHH', total_len, PDU_TYPE_DATA, self.user_id & 0xFFFF)
            rdp = struct.pack('<HH', 0, 0) + share_ctrl + inner  # null sec header
            return self._mcs_send_data(rdp)

        # Synchronize PDU (pduType2=0x1F)
        sync     = rdp_data_pdu(0x1F, struct.pack('<HH', 1, self.user_id & 0xFFFF))
        # Control PDU — cooperate (action=4)
        coop     = rdp_data_pdu(0x14, struct.pack('<HHI', 4, 0, 0))
        # Control PDU — granted control (action=2)
        granted  = rdp_data_pdu(0x14, struct.pack('<HHI', 2, self.user_id & 0xFFFF, SHARE_ID))
        # Font Map PDU (pduType2=0x28)
        font_map = rdp_data_pdu(0x28, struct.pack('<HHHH', 0, 0, 0x0003, 0x0004))

        return [sync, coop, granted, font_map]

    # ── ClientInfo parser ────────────────────────────────────────────────────

    def _parse_client_info(self, tpkt_data):
        """
        Extract username, password, domain from a ClientInfo PDU.
        MS-RDPBCGR §2.2.1.11 — TS_INFO_PACKET

        For plain RDP (no encryption), the InfoPacket is in cleartext after
        the MCS SendDataRequest and Basic Security Header.
        """
        try:
            # Skip TPKT(4) + X224(3) + MCS SendDataRequest header (variable)
            # MCS SDR: 0x64 + initiator(2) + channelId(2) + dataPriority(1) + segmentation(1) + length(2) = 9 bytes
            if len(tpkt_data) < 20:
                return None

            # Find start of RDP data after MCS header
            rdp_offset = 7  # TPKT+X224
            if tpkt_data[rdp_offset] != 0x64:
                return None
            rdp_offset += 9  # skip MCS SDR header (9 bytes typical)

            # Basic Security Header: flags(2) + flagsHi(2) = 4 bytes
            if rdp_offset + 4 > len(tpkt_data):
                return None
            sec_flags = struct.unpack('<H', tpkt_data[rdp_offset:rdp_offset+2])[0]
            rdp_offset += 4

            # INFO_PKT flag = 0x0040, or just try to parse regardless
            if rdp_offset + 18 > len(tpkt_data):
                return None

            info_data = tpkt_data[rdp_offset:]

            # TS_INFO_PACKET layout:
            # CodePage(4) + flags(4) + cbDomain(2) + cbUserName(2) +
            # cbPassword(2) + cbAlternateShell(2) + cbWorkingDir(2) +
            # Domain(cbDomain+2) + UserName(cbUserName+2) + Password(cbPassword+2)
            if len(info_data) < 18:
                return None

            code_page = struct.unpack('<I', info_data[0:4])[0]
            flags     = struct.unpack('<I', info_data[4:8])[0]
            cb_domain   = struct.unpack('<H', info_data[8:10])[0]
            cb_username = struct.unpack('<H', info_data[10:12])[0]
            cb_password = struct.unpack('<H', info_data[12:14])[0]
            cb_altshell = struct.unpack('<H', info_data[14:16])[0]
            cb_workdir  = struct.unpack('<H', info_data[16:18])[0]

            self.log_debug(f"ClientInfo header: flags=0x{flags:08x} "
                           f"cbDomain={cb_domain} cbUser={cb_username} cbPass={cb_password}")

            offset = 18
            # Strings are null-terminated UTF-16LE; cb* is byte length WITHOUT the null terminator

            def read_utf16(data, off, cb):
                if off + cb + 2 > len(data):
                    return "", off + cb + 2
                raw = data[off:off+cb]
                try:
                    return raw.decode('utf-16-le', errors='replace').rstrip('\x00'), off + cb + 2
                except Exception:
                    return raw.hex(), off + cb + 2

            domain,   offset = read_utf16(info_data, offset, cb_domain)
            username, offset = read_utf16(info_data, offset, cb_username)
            password, offset = read_utf16(info_data, offset, cb_password)

            if not username and not password:
                return None

            return {
                'username': username,
                'password': password,
                'domain':   domain,
            }

        except Exception as e:
            self.log_debug(f"ClientInfo parse exception: {e}")
            return None

    # -------------------------------------------------------------------------
    # Phase 5 — Credential capture / session keep-alive
    # -------------------------------------------------------------------------

    def _phase5_authentication_session(self):
        """
        By the time we reach Phase 5, credentials should already be captured
        from the ClientInfo PDU in Phase 4. This phase just keeps the session
        alive long enough for Windows to show a desktop (or error), and
        catches any late-arriving data that might contain credentials.
        """
        self.log_phase(5, "Entering authentication session phase")
        try:
            self.client_socket.settimeout(30.0)
            session_start = time.time()

            while time.time() - session_start < 120:
                try:
                    data = self._recv_tpkt()
                    if not data:
                        break

                    self.log_debug("Phase5 recv", data)

                    # Try credential extraction on every received PDU
                    creds = self._parse_client_info(data)
                    if creds:
                        self.log_phase(5, f"Late credential capture: {creds}")
                        self.credentials_captured.append({
                            'timestamp': datetime.datetime.now().isoformat(),
                            'client_addr': self.client_addr,
                            'credentials': creds,
                        })
                        self._save_credentials_dict(creds)

                    # Also try raw text extraction as fallback
                    raw_creds = self._extract_credentials_from_data(data)
                    if raw_creds:
                        self.log_debug(f"Raw text credentials: {raw_creds}")

                except socket.timeout:
                    self.log_debug("Phase5 timeout — session quiet")
                    break

        except Exception as e:
            self.logger.error(f"Phase5 exception: {e}")

    def _extract_credentials_from_data(self, data):
        """Fallback raw ASCII scan for any printable text in a PDU."""
        try:
            segments, cur = [], bytearray()
            for b in data:
                if 32 <= b <= 126:
                    cur.append(b)
                else:
                    if len(cur) > 3:
                        try: segments.append(cur.decode('ascii'))
                        except Exception: pass
                    cur = bytearray()
            if len(cur) > 3:
                try: segments.append(cur.decode('ascii'))
                except Exception: pass
            return [s.strip() for s in segments if len(s.strip()) >= 3] or None
        except Exception as e:
            self.log_debug(f"Raw credential scan exception: {e}")
            return None

    def _save_credentials_dict(self, creds):
        """Save a structured credentials dict to file and warning log."""
        try:
            self.logger.warning(
                f"CREDENTIALS — user={creds.get('username')!r} "
                f"pass={creds.get('password')!r} domain={creds.get('domain')!r} "
                f"src={self.client_addr}",
                extra={"src_ip_addr": self.client_addr[0], "src_port": self.client_addr[1]}
            )
            os.makedirs('logs', exist_ok=True)
            with open('logs/captured_credentials.txt', 'a', encoding='utf-8') as f:
                ts = datetime.datetime.now().isoformat()
                f.write(f"\n=== {ts} ===\n")
                f.write(f"Client:   {self.client_addr}\n")
                f.write(f"Domain:   {creds.get('domain', '')}\n")
                f.write(f"Username: {creds.get('username', '')}\n")
                f.write(f"Password: {creds.get('password', '')}\n")
        except Exception as e:
            self.logger.error(f"Save credentials exception: {e}")

    def _cleanup(self):
        try:
            self.client_socket.close()
        except Exception:
            pass
        self.log_phase(0, f"Connection from {self.client_addr} closed")
        if self.connection_established:
            self.logger.info(f"Session summary — client: {self.client_addr}, "
                             f"credentials captured: {len(self.credentials_captured)}")


# =============================================================================
# Server
# =============================================================================

class RDPHoneypotFreeRDP:

    def __init__(self, host='0.0.0.0', port=3389, log_level=logging.INFO):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False

        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/rdp_honeypot_freerdp.log'),
                logging.StreamHandler(),
            ]
        )
        self.logger = logging.getLogger('rdp_honeypot_freerdp')

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.running = True

            self.logger.info("=" * 60)
            self.logger.info(f"RDP Honeypot started — {self.host}:{self.port}")
            self.logger.info("=" * 60)

            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    self.logger.info(f"New connection: {client_addr}")
                    try:
                        logger.warning("New connection", extra={
                            "src_ip_addr": client_addr[0],
                            "src_port": client_addr[1],
                        })
                    except Exception:
                        pass

                    t = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True,
                    )
                    t.start()

                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept exception: {e}")

        except Exception as e:
            self.logger.error(f"Server start failed: {e}")
        finally:
            self.stop()

    def _handle_client(self, client_socket, client_addr):
        try:
            protocol = RDPProtocolFreeRDP(client_socket, client_addr, self.logger)
            protocol.handle_connection()
        except Exception as e:
            import traceback
            self.logger.error(f"Handle client {client_addr}: {e}")
            self.logger.error(traceback.format_exc())
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.logger.info("RDP Honeypot stopped")


def parse_args():
    if len(sys.argv) >= 4:
        return int(sys.argv[1]), sys.argv[2], sys.argv[3]
    return 3389, "honeypot", "0.0.0.0"


if __name__ == "__main__":
    port, name, dst_ip = parse_args()
    log_file = f"/log/rdp{port}.log"
    logger = build_logger(name, log_file, dst_ip, port)

    honeypot = RDPHoneypotFreeRDP(host='0.0.0.0', port=port, log_level=logging.DEBUG)
    try:
        honeypot.start()
    except KeyboardInterrupt:
        print("\nStopping...")
        honeypot.stop()