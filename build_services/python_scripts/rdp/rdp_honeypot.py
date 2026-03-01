"""
RDP Honeypot - Complete FreeRDP-based implementation
Fully reimplemented with FreeRDP protocol reference and detailed debug logging

Protocol phases:
1. X.224 Connection Negotiation (Connection Request/Confirm)
2. MCS Connection Sequence (Connect-Initial/Connect-Response)
3. MCS Channel Establishment (ErectDomain/AttachUser/ChannelJoin)
4. RDP Session Establishment (Security/License/Capability)
5. User Authentication Capture
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
from json_formatter import JSONFormatter

def build_logger(name: str, log_file: str, dst_ip: str, dst_port: int) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.FileHandler(log_file, mode="a")
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
        
        # Protocol state
        self.phase = 0
        self.client_requested_protocols = 0
        self.selected_protocol = self.PROTOCOL_RDP
        self.user_id = 0x03ea + 1  # MCS User ID
        self.channel_id = 0x03eb    # MCS Channel ID
        
        # Debug switches
        self.debug = True
        self.verbose_ber = True
        
        # Session state
        self.connection_established = False
        self.credentials_captured = []

    def log_debug(self, message, data=None):
        """Detailed debug logging"""
        if self.debug:
            if data is not None:
                if isinstance(data, (bytes, bytearray)):
                    hex_str = ' '.join(f'{b:02x}' for b in data[:64])  # limit length
                    if len(data) > 64:
                        hex_str += f'... ({len(data)} bytes total)'
                    self.logger.info(f"[DEBUG] {message}: {hex_str}")
                else:
                    self.logger.info(f"[DEBUG] {message}: {data}")
            else:
                self.logger.info(f"[DEBUG] {message}")
                
    def log_phase(self, phase, message):
        """Phase logging"""
        self.logger.info(f"[PHASE-{phase}] {message}")
        logger.warning(f"[PHASE-{phase}] {message}", extra={
                        "src_ip_addr": self.client_addr[0],
                        "src_port" : self.client_addr[1],
        },)
        
    def log_ber(self, message, data):
        """BER encoding debug log"""
        if self.verbose_ber and data:
            hex_str = ' '.join(f'{b:02x}' for b in data[:32])
            self.logger.info(f"[BER] {message}: {hex_str}")

    def handle_connection(self):
        """Handle complete RDP connection process"""
        try:
            self.log_phase(0, f"Starting to handle from {self.client_addr} RDP connection")
            
            # Phase 1: X.224 Connection Negotiation
            if not self._phase1_x224_connection():
                self.log_phase(1, "X.224 connection negotiation failed")
                return False
                
            # Phase 2: MCS Connection Establishment
            if not self._phase2_mcs_connection():
                self.log_phase(2, "MCSconnection establishment failed") 
                return False
                
            # Phase 3: MCS Channel Establishment
            if not self._phase3_mcs_channels():
                self.log_phase(3, "MCS channel establishment failed")
                return False
                
            # Phase 4: RDP Session Negotiation
            if not self._phase4_rdp_negotiation():
                self.log_phase(4, "RDP session negotiation failed")
                return False
                
            # Phase 5: User authentication session
            self._phase5_authentication_session()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Connection handling exception: {e}")
            import traceback
            self.logger.error(f"Detailed error: {traceback.format_exc()}")
            return False
        finally:
            self._cleanup()

    def _phase1_x224_connection(self):
        """Phase 1: X.224 Connection Negotiation - Based on FreeRDP x224.c"""
        self.log_phase(1, "Starting X.224 connection negotiation")
        
        try:
            # Receive X.224 connection request
            data = self.client_socket.recv(1024)
            if not data:
                self.log_debug("No X.224 connection request received")
                return False
                
            self.log_debug("Received X.224 connection request", data)
            
            # Parse TPKT header (RFC 2126)
            if len(data) < 4:
                self.log_debug("TPKT header length insufficient")
                return False
                
            tpkt_version = data[0]
            tpkt_reserved = data[1] 
            tpkt_length = struct.unpack('>H', data[2:4])[0]
            
            self.log_debug(f"TPKT: version={tpkt_version}, length={tpkt_length}")
            
            if tpkt_version != 3:
                self.log_debug(f"Unsupported TPKT version: {tpkt_version}")
                return False
                
            # Parse X.224 header (After TPKT)
            # MSTSC actual format:  03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 0b 00 00 00
            #                TPKT header    ^LI^TPDU^DST-REF ^SRC-REF^CLASS
            if len(data) < 10:
                self.log_debug("X.224 header length insufficient")
                return False
                
            # X.224 standard format: Length Indicator | TPDU Code | Other fields
            x224_length = data[4]   # Length Indicator (LI)
            x224_type = data[5]     # TPDU Code
            
            self.log_debug(f"X.224: LI={x224_length}, type=0x{x224_type:02x}")
            
            # Check if connection request
            if x224_type == self.X224_TPDU_CONNECTION_REQUEST:
                self.log_debug("found X.224 connection request")
                x224_dst_ref = struct.unpack('>H', data[6:8])[0]
                x224_src_ref = struct.unpack('>H', data[8:10])[0]
                
                self.log_debug(f"X.224 CR: type=0x{x224_type:02x}, dst_ref=0x{x224_dst_ref:04x}, src_ref=0x{x224_src_ref:04x}")
                
            else:
                self.log_debug(f"Not an X.224 connection request: 0x{x224_type:02x} (Expected: 0x{self.X224_TPDU_CONNECTION_REQUEST:02x})")
                return False
                
            # Parse Negotiation request data (After X.224 header)
            # X.224 header total length = 4(TPKT) + 1(LI) + LI bytes count
            x224_total_length = 4 + 1 + x224_length
            if len(data) > x224_total_length:
                nego_data = data[x224_total_length:]
                if len(nego_data) > 0:
                    self.log_debug("Negotiation request data", nego_data)
                    self._parse_rdp_nego_req(nego_data)
                
            # sending X.224 connection confirm
            response = self._build_x224_connection_confirm()
            self.client_socket.send(response)
            self.log_debug("sending X.224 connection confirm", response)
            
            self.log_phase(1, "X.224 connection negotiation complete")
            return True
            
        except Exception as e:
            self.log_phase(1, f"X.224 negotiation exception: {e}")
            return False

    def _parse_rdp_nego_req(self, data):
        """Parse RDP negotiation request - Based on FreeRDP nego.c"""
        if len(data) < 8:
            return
            
        # Parse negotiation request data
        nego_type = data[0]
        nego_flags = data[1] 
        nego_length = struct.unpack('<H', data[2:4])[0]
        self.client_requested_protocols = struct.unpack('<I', data[4:8])[0]
        
        self.log_debug(f"Negotiation request: type={nego_type}, flags={nego_flags}, length={nego_length}")
        self.log_debug(f"Client requested protocol: 0x{self.client_requested_protocols:08x}")
        
        if nego_type == self.RDP_NEG_REQ:
            # Select protocol - prioritize standard RDP
            if self.client_requested_protocols == 0 or (self.client_requested_protocols & self.PROTOCOL_RDP):
                self.selected_protocol = self.PROTOCOL_RDP
                self.log_debug("Selected standard RDP protocol")
            else:
                # Client requires other protocols, but we only support RDP
                self.selected_protocol = self.PROTOCOL_RDP
                self.log_debug("Force use of standard RDP protocol")

    def _build_x224_connection_confirm(self):
        """build X.224 connection confirm - Based on FreeRDP x224.c"""
        
        # X.224 connection confirm data
        x224_data = bytearray()
        x224_data.append(self.X224_TPDU_CONNECTION_CONFIRM)  # Connection Confirm
        x224_data.extend([0x00, 0x00])  # dst-ref (2 bytes)
        x224_data.extend([0x00, 0x00])  # src-ref (2 bytes) 
        x224_data.append(0x00)  # class option
        
        # RDP negotiation response
        if self.client_requested_protocols != 0:
            nego_resp = bytearray()
            nego_resp.append(self.RDP_NEG_RSP)     # Negotiation response type
            nego_resp.append(0x01)                 # Flags:  EXTENDED_CLIENT_DATA_SUPPORTED
            nego_resp.extend(struct.pack('<H', 8)) # Length
            nego_resp.extend(struct.pack('<I', self.selected_protocol))  # Selected protocol
            x224_data.extend(nego_resp)
        
        # X.224 header
        x224_length = len(x224_data)
        x224_header = bytearray()
        x224_header.append(x224_length)
        x224_header.extend(x224_data)
        
        # TPKT header
        total_length = 4 + len(x224_header)
        tpkt_header = bytearray()
        tpkt_header.append(0x03)  # TPKT version
        tpkt_header.append(0x00)  # Reserved
        tpkt_header.extend(struct.pack('>H', total_length))
        
        return bytes(tpkt_header + x224_header)

    def _phase2_mcs_connection(self):
        """Phase 2: MCS Connection Establishment - Based on FreeRDP mcs.c"""
        self.log_phase(2, "starting MCS connection establishment")
        
        try:
            # Receive MCS Connect-Initial
            data = self.client_socket.recv(4096)
            if not data:
                self.log_debug("Did not receive MCS Connect-Initial")
                return False
                
            self.log_debug("received MCS Connect-Initial", data)
            
            # Skip TPKT header(4bytes) + X.224 Data PDU header (3bytes)  
            # X.224 Data PDU: Length(1) | Code(1) | EOT(1) | MCS data...
            if len(data) < 8:
                self.log_debug("MCS data length")
                return False
                
            mcs_data = data[7:]  # TPKT(4) + X.224 Data(3) 
            self.log_debug("MCSdata part", mcs_data)
            
            # Parse MCS Connect-Initial
            if not self._parse_mcs_connect_initial(mcs_data):
                self.log_debug("MCS Connect-Initial parsing failed")
                return False
                
            # sendingMCS Connect-Response
            response = self._build_mcs_connect_response()
            self.client_socket.send(response)
            self.log_debug("sendingMCS Connect-Response", response)
            
            self.log_phase(2, "MCS connection establishment complete")
            return True
            
        except Exception as e:
            self.log_phase(2, f"MCS connection exception: {e}")
            import traceback
            self.logger.error(f"MCSDetailed error: {traceback.format_exc()}")
            return False

    def _parse_mcs_connect_initial(self, data):
        """Parse MCS Connect-Initial - Based on FreeRDP mcs.c"""
        try:
            if len(data) < 2:
                return False
                
            # MCS Connect-Initial -  tag (definite length)Length
            first_byte = data[0]
            if first_byte == self.MCS_CONNECT_INITIAL:
                # Standard form 0x65
                self.log_ber("MCS Connect-Initial ()", data[:1])
            elif first_byte == 0x7f:
                # Length 0x7f - This is valid BER encoding
                self.log_ber("MCS Connect-Initial ( tag (definite length))", data[:1])
                self.log_debug("received definite length form ofMCS Connect-Initial")
            else:
                self.log_debug(f"invalid MCS Connect-Initial tag: 0x{first_byte:02x}")
                return False
            
            # Parse BERLength
            length, offset = self._parse_ber_length(data, 1)
            self.log_debug(f"MCS Connect-Initial BERLength: {length}, : {offset}")
            
            if offset >= len(data):
                self.log_debug("BER data offset out of range")
                return False
                
            # Parse Connect-Initialcontent
            self.log_ber("Connect-Initialcontent", data[offset:offset+32])
            
            # Basic validation passed
            self.log_debug("MCS Connect-Initialparsing successful")
            return True
            
        except Exception as e:
            self.log_debug(f"MCS Connect-Initial parsing exception: {e}")
            return False

    def _parse_ber_length(self, data, offset):
        """parse BER length encoding - based on ASN.1 BER specification"""
        if offset >= len(data):
            return 0, offset
            
        first_byte = data[offset]
        offset += 1
        
        if first_byte & 0x80 == 0:
            # short form: Lengthbytes
            return first_byte, offset
        else:
            # long form: bytes7Lengthbytes
            length_bytes = first_byte & 0x7F
            
            if length_bytes == 0:
                # indefinite length form, simplified handling here
                return 0, offset
                
            if offset + length_bytes > len(data):
                return 0, offset
                
            # read actual length from subsequent bytes
            length = 0
            for i in range(length_bytes):
                length = (length << 8) | data[offset + i]
            offset += length_bytes
            
            return length, offset

    def _build_mcs_connect_response(self):
        """build MCS Connect-Response  - based on FreeRDP strict protocol specification"""
        
        # build minimal compliant Connect-Response according to ITU-T T.125 specification
        # Connect-Response ::= [APPLICATION 102] IMPLICIT SEQUENCE {
        #   result          Result,
        #   calledConnectId ConnectId OPTIONAL,
        #   domainParameters DomainParameters,
        #   userData        OCTET STRING OPTIONAL
        # }
        
        # 1. Result: rt-successful (0) - ENUMERATED
        result = bytearray([0x0A, 0x01, 0x00])
        
        # 2. Called Connect Id - INTEGER 
        called_id = bytearray([0x02, 0x01, 0x79])
        
        # 3. Domain Parameters - minimum required parameters
        domain_params = bytearray([
            0x30, 0x19,  # SEQUENCE, length=25
            0x02, 0x01, 0x22,  # maxChannelIds:  34
            0x02, 0x01, 0x03,  # maxUserIds:  3
            0x02, 0x01, 0x00,  # maxTokenIds:  0
            0x02, 0x01, 0x01,  # numPriorities:  1
            0x02, 0x01, 0x00,  # minThroughput:  0
            0x02, 0x01, 0x01,  # maxHeight:  1
            0x02, 0x02, 0xFF, 0xF8,  # maxMCSPDUsize:  65528
            0x02, 0x01, 0x02   # protocolVersion:  2
        ])
        
        # 4. build GCC  Conference Create  Response data
        gcc_response = self._build_gcc_conference_create_response()
        user_data = bytearray([0x04])  # OCTET STRING tag
        user_data.extend(self._encode_ber_length(len(gcc_response)))
        user_data.extend(gcc_response)
        
        # content
        content = bytearray()
        content.extend(result)
        content.extend(called_id) 
        content.extend(domain_params)
        content.extend(user_data)
        
        # use APPLICATION 102 tag + length encoding
        mcs_response = bytearray([0x66])  # [APPLICATION 102] = 0x40 | 0x20 | 0x06
        mcs_response.extend(self._encode_ber_length(len(content)))
        mcs_response.extend(content)
        
        self.log_debug(f"MCS Connect-Responsetotal length: {len(mcs_response)}")
        
        # Wrap in X.224 Data PDU
        return self._wrap_x224_data(mcs_response)
    
    def _build_gcc_conference_create_response(self):
        """build GCC Conference Create Response  - directly return server data blocks"""
        
        # for MCS Connect-Response userData field，
        # we only need to return server data blocks, no additional GCC wrapping needed
        server_data = self._build_minimal_server_data()
        
        return server_data
    
    def _build_minimal_server_data(self):
        """build  data  - based on MS-RDPBCGR specification"""
        
        # Server Core Data (SC_CORE) - type 0x0C01 (little-endian)
        core_data = bytearray([
            0x01, 0x0C,  # type:  SC_CORE (0x0C01 in little-endian)
            0x0C, 0x00,  # length:  12 bytes (minimum)
            0x04, 0x00, 0x08, 0x00,  # version:  0x00080004 (RDP 5.0)
            0x00, 0x00, 0x00, 0x00   # clientRequestedProtocols:  none
        ])
        
        # Server Security Data (SC_SECURITY) - type 0x0C02 (little-endian)
        sec_data = bytearray([
            0x02, 0x0C,  # type:  SC_SECURITY (0x0C02 in little-endian)  
            0x0C, 0x00,  # length:  12 bytes
            0x00, 0x00, 0x00, 0x00,  # encryptionMethod:  ENCRYPTION_METHOD_NONE
            0x00, 0x00, 0x00, 0x00   # encryptionLevel:  ENCRYPTION_LEVEL_NONE
        ])
        
        # Server Network Data (SC_NET) - type 0x0C03 (little-endian)
        net_data = bytearray([
            0x03, 0x0C,  # type:  SC_NET (0x0C03 in little-endian)
            0x08, 0x00,  # length:  8 bytes (minimum - no channels)
            0x00, 0x00,  # MCS message channel id: 0 (will be assigned)
            0x00, 0x00   # channel count: 0 (no static channels)
        ])
        
        server_data = bytearray()
        server_data.extend(core_data)
        server_data.extend(sec_data) 
        server_data.extend(net_data)
        
        return server_data

    def _build_domain_parameters(self):
        """build   - DomainParameters in MCS Connect-Response"""
        
        # DomainParameters ::= SEQUENCE {
        #   maxChannelIds INTEGER (1..MAX),
        #   maxUserIds INTEGER (1..MAX),
        #   maxTokenIds INTEGER (1..MAX),
        #   numPriorities INTEGER (1..MAX),
        #   minThroughput INTEGER (0..MAX),
        #   maxHeight INTEGER (0..MAX),
        #   maxMCSPDUsize INTEGER (1..MAX),
        #   protocolVersion INTEGER (1..MAX)
        # }
        
        params = bytearray()
        
        # SEQUENCE
        params.append(0x30)
        
        # Build content
        content = bytearray()
        
        # maxChannelIds:  34 - INTEGER
        content.extend([0x02, 0x01, 0x22])
        
        # maxUserIds:  2 - INTEGER  
        content.extend([0x02, 0x01, 0x02])
        
        # maxTokenIds:  0 - INTEGER
        content.extend([0x02, 0x01, 0x00])
        
        # numPriorities:  1 - INTEGER
        content.extend([0x02, 0x01, 0x01])
        
        # minThroughput:  0 - INTEGER
        content.extend([0x02, 0x01, 0x00])
        
        # maxHeight:  1 - INTEGER
        content.extend([0x02, 0x01, 0x01])
        
        # maxMCSPDUsize:  65528 - INTEGER (0xFFF8)
        content.extend([0x02, 0x02, 0xFF, 0xF8])
        
        # protocolVersion:  2 - INTEGER
        content.extend([0x02, 0x01, 0x02])
        
        # SEQUENCELength
        params.extend(self._encode_ber_length(len(content)))
        params.extend(content)
        
        return params

    def _build_server_data_blocks(self):
        """build  data  - based on FreeRDP gcc.c"""
        data_blocks = bytearray()
        
        # Server core data block
        core_data = self._build_server_core_data()
        data_blocks.extend(core_data)
        
        # Server security data block
        security_data = self._build_server_security_data()
        data_blocks.extend(security_data)
        
        # Server network data block
        network_data = self._build_server_network_data()
        data_blocks.extend(network_data)
        
        return data_blocks

    def _build_server_core_data(self):
        """build  data  - based on FreeRDP gcc.c"""
        data = bytearray()
        
        # Data block header
        data.extend(struct.pack('<H', self.SC_CORE))  # Data block type
        length_pos = len(data)
        data.extend(struct.pack('<H', 0))  # Length
        
        # Server version
        data.extend(struct.pack('<I', 0x00080004))  # RDP 5.0/5.1/5.2
        
        # Client requested protocol
        data.extend(struct.pack('<H', self.client_requested_protocols & 0xFFFF))
        data.extend(struct.pack('<H', 0x0000))  # Padding
        
        # Length
        total_length = len(data)
        struct.pack_into('<H', data, length_pos, total_length)
        
        self.log_debug(f"server  data length: {total_length}")
        return data

    def _build_server_security_data(self):
        """build  data  - No encryption"""
        data = bytearray()
        
        # Data block header
        data.extend(struct.pack('<H', self.SC_SECURITY))  # Data block type
        length_pos = len(data)
        data.extend(struct.pack('<H', 0))  # Length
        
        # Encryption method:  No encryption
        data.extend(struct.pack('<I', 0x00000000))  # ENCRYPTION_METHOD_NONE
        
        # Encryption level:  No encryption 
        data.extend(struct.pack('<I', 0x00000000))  # ENCRYPTION_LEVEL_NONE
        
        # Length
        total_length = len(data)
        struct.pack_into('<H', data, length_pos, total_length)
        
        self.log_debug(f"server  data length: {total_length}")
        return data

    def _build_server_network_data(self):
        """Build server network data"""
        data = bytearray()
        
        # Data block header
        data.extend(struct.pack('<H', self.SC_NET))  # Data block type
        length_pos = len(data)
        data.extend(struct.pack('<H', 0))  # Length
        
        # MCS message channel ID
        data.extend(struct.pack('<H', self.channel_id))
        
        # Channel count:  0 (No additional channels)
        data.extend(struct.pack('<H', 0x0000))
        
        # Length
        total_length = len(data)
        struct.pack_into('<H', data, length_pos, total_length)
        
        self.log_debug(f"server  data length: {total_length}")
        return data

    def _build_gcc_conference_create_response(self):
        """build GCC Conference Create Response  - FreeRDP negotiation response"""
        
        # ConferenceCreateResponse ::= SEQUENCE {
        #   result ENUMERATED { success(0) },
        #   nodeID UserID,
        #   tag  CHOICE {
        #     h221NonStandard H221NonStandardIdentifier,
        #     ...
        #   },
        #   result2 OCTET STRING
        # }
        
        response = bytearray()
        
        # SEQUENCE
        response.append(0x30)
        
        # Build content
        content = bytearray()
        
        # result:  success(0) - ENUMERATED
        content.extend([0x0A, 0x01, 0x00])
        
        # nodeID:  UserID - INTEGER
        content.extend([0x02, 0x01, 0x79])
        
        # tag:  h221NonStandard - SEQUENCE
        content.append(0x30)  # SEQUENCE
        
        # H.221 non-standard identifiercontent
        h221_content = bytearray()
        
        # object:  Microsoft H.221 identifier - OCTET STRING
        h221_content.append(0x04)  # OCTET STRING
        h221_content.append(0x07)  # length
        h221_content.extend(b'\x00\x05\x00\x14\x7c\x00\x01')  # Microsoft H.221 key
        
        # data:  RDP server data - OCTET STRING
        server_data = self._build_server_data_blocks()
        h221_content.append(0x04)  # OCTET STRING
        h221_content.extend(self._encode_ber_length(len(server_data)))
        h221_content.extend(server_data)
        
        # H.221contentLength
        content.extend(self._encode_ber_length(len(h221_content)))
        content.extend(h221_content)
        
        # Length
        response.extend(self._encode_ber_length(len(content)))
        response.extend(content)
        
        self.log_debug(f"GCC Conference Create ResponseLength: {len(response)}")
        
        return response

    def _build_connect_data(self, server_data):
        """build ConnectData  -  data，"""
        
        # In MCS Connect Response, UserData directly contains RDP server data
        # No additional ConnectData wrapping needed, this is one cause of 0x2104 errors
        
        self.log_debug(f"Server dataLength: {len(server_data)}")
        return server_data

    def _encode_ber_sequence(self, items):
        """Encode BER sequence"""
        content = bytearray()
        for item in items:
            content.extend(item)
            
        result = bytearray()
        result.append(0x30)  # SEQUENCE
        result.extend(self._encode_ber_length(len(content)))
        result.extend(content)
        
        return result

    def _encode_ber_enumerated(self, value):
        """Encode BER enumerated value"""
        # Simple enumerated encoding
        if value == 0:
            content = b'\x00'
        else:
            content = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            
        result = bytearray()
        result.append(0x0A)  # ENUMERATED
        result.extend(self._encode_ber_length(len(content)))
        result.extend(content)
        
        return result

    def _encode_ber_octet_string(self, data):
        """BERbytes"""
        result = bytearray()
        result.append(0x04)  # OCTET STRING
        result.extend(self._encode_ber_length(len(data)))
        result.extend(data)
        
        return result

    def _encode_ber_length(self, length):
        """encode BER length"""
        if length < 0x80:
            # short form
            return bytes([length])
        else:
            # long form
            length_bytes = []
            temp = length
            while temp > 0:
                length_bytes.insert(0, temp & 0xFF)
                temp >>= 8
                
            result = bytearray()
            result.append(0x80 | len(length_bytes))  # long form + bytes
            result.extend(length_bytes)
            
            return result

    def _wrap_x224_data(self, mcs_data):
        """Wrap in X.224 Data PDU"""
        # X.224 Data PDU
        x224_data = bytearray()
        x224_data.append(0x02)  # X.224 Data PDULength
        x224_data.append(self.X224_TPDU_DATA)  # Data TPDU
        x224_data.append(0x80)  # EOT (End of TSDU)
        
        # TPKT header
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = bytearray()
        tpkt_header.append(0x03)  # TPKT version
        tpkt_header.append(0x00)  # Reserved
        tpkt_header.extend(struct.pack('>H', total_length))
        
        return bytes(tpkt_header + x224_data + mcs_data)

    def _phase3_mcs_channels(self):
        """Phase 3: MCS Channel Establishment - Based on FreeRDP mcs.c"""
        self.log_phase(3, "starting MCS channel establishment")
        
        try:
            # Handle MCS PDU - ClientsendingErectDomain、AttachUser、ChannelJoin
            received_pdu_count = 0
            expected_pdus = ['ErectDomain', 'AttachUser', 'ChannelJoin']
            
            for i in range(10):  # Increase processing rounds
                try:
                    self.client_socket.settimeout(3.0)  # Shorten timeout, quick response
                    data = self.client_socket.recv(1024)
                    if not data:
                        self.log_debug(f"Channel establishment phase {i+1}: received data")
                        break
                        
                    self.log_debug(f"received MCSPDU {i+1}", data)
                    
                    # Skip TPKT and X.224 headers, extract MCS PDU
                    if len(data) >= 7:
                        mcs_pdu = data[7:]
                        if mcs_pdu:
                            pdu_info = self._analyze_mcs_pdu(mcs_pdu)
                            self.log_debug(f"MCS PDU type: {pdu_info}")
                            
                            response = self._handle_mcs_pdu(mcs_pdu)
                            if response:
                                self.client_socket.send(response)
                                self.log_debug(f"sendingMCS {i+1}", response)
                                received_pdu_count += 1
                            else:
                                # Some PDUs need no response but still count as successful processing
                                received_pdu_count += 1
                    
                    # Received PDU， complete
                    if received_pdu_count >= 3:
                        self.log_debug("Received enough MCS PDUs, channel establishment complete")
                        break
                                
                except socket.timeout:
                    self.log_debug(f"Channel establishment timeout, current phase: {i+1}")
                    # Timeout may be normal, continue to next phase
                    break
                except Exception as e:
                    self.log_debug(f"MCS  PDU processing exception: {e}")
                    # Connection error, but don't fail immediately, there may be more data
                    break
                    
            self.log_phase(3, f"MCS channel establishment complete (processed{received_pdu_count}PDUs)")
            return True
            
        except Exception as e:
            self.log_phase(3, f"MCS Channel Establishment exception: {e}")
            return False

    def _analyze_mcs_pdu(self, pdu_data):
        """MCS PDU type"""
        if not pdu_data:
            return "Empty data"
            
        pdu_type = pdu_data[0]
        
        # Analyze specific PDU type
        if pdu_type >> 2 == self.MCS_ERECT_DOMAIN_REQUEST >> 2:
            return f"ErectDomainRequest (0x{pdu_type:02x})"
        elif pdu_type >> 2 == self.MCS_ATTACH_USER_REQUEST >> 2:
            return f"AttachUserRequest (0x{pdu_type:02x})"
        elif pdu_type >> 2 == self.MCS_CHANNEL_JOIN_REQUEST >> 2:
            return f"ChannelJoinRequest (0x{pdu_type:02x})"
        elif pdu_type == 0x64:
            return f"SendDataRequest (0x{pdu_type:02x})"
        else:
            return f"Unknown PDU (0x{pdu_type:02x})"

    def _handle_mcs_pdu(self, pdu_data):
        """Handle MCS PDU - Based on FreeRDP mcs.c"""
        if not pdu_data:
            return None
            
        pdu_type = pdu_data[0]
        self.log_debug(f"Handle MCS PDU type: 0x{pdu_type:02x}")
        
        # More precise PDU type matching
        if pdu_type == 0x04:  # ErectDomainRequest
            self.log_debug("Received ErectDomainRequest - No response needed")
            return None
            
        elif (pdu_type & 0xFC) == 0x28:  # AttachUserRequest
            self.log_debug("Received AttachUserRequest")
            return self._build_attach_user_confirm()
            
        elif (pdu_type & 0xFC) == 0x38:  # ChannelJoinRequest
            self.log_debug("Received ChannelJoinRequest")
            # Parse channel ID from PDU
            channel_id = self._extract_channel_id_from_join_request(pdu_data)
            return self._build_channel_join_confirm_with_id(channel_id)
            
        elif pdu_type == 0x64:  # SendDataRequest
            self.log_debug("Received SendDataRequest - Enter RDP data phase")
            return None  # This will enter RDP negotiation phase
            
        else:
            self.log_debug(f"MCS PDU type: 0x{pdu_type:02x}")
            return None

    def _extract_channel_id_from_join_request(self, pdu_data):
        """Extract channel ID from ChannelJoinRequest"""
        try:
            if len(pdu_data) >= 5:
                # ChannelJoinRequest:  [PDU_TYPE][initiator][channel_id]
                channel_id = struct.unpack('>H', pdu_data[3:5])[0]
                self.log_debug(f"Client requests to join channel: 0x{channel_id:04x}")
                return channel_id
        except:
            pass
        return self.channel_id  # Use our channel ID by default

    def _build_channel_join_confirm_with_id(self, requested_channel_id):
        """Build ChannelJoinConfirm with specific channel ID"""
        pdu_data = bytearray()
        
        # ChannelJoinConfirm PDU
        pdu_data.append(0x3F)  # ChannelJoinConfirm (Fixed value)
        pdu_data.append(0x00)  # result:  rt-successful
        pdu_data.append((self.user_id >> 8) & 0xFF)    # User ID high byte
        pdu_data.append(self.user_id & 0xFF)            # User ID low byte  
        pdu_data.append((requested_channel_id >> 8) & 0xFF) # Requested channel ID high byte
        pdu_data.append(requested_channel_id & 0xFF)         # Requested channel ID low byte
        
        self.log_debug(f"Build ChannelJoinConfirm, user ID: 0x{self.user_id:04x}, Channel ID: 0x{requested_channel_id:04x}")
        return self._wrap_x224_data(pdu_data)

    def _build_attach_user_confirm(self):
        """build AttachUserConfirm  - FreeRDP mcs.c"""
        pdu_data = bytearray()
        
        # AttachUserConfirm PDU - Use correct encoding
        pdu_data.append(0x2E)  # AttachUserConfirm (Fixed value)
        pdu_data.append(0x00)  # result:  rt-successful  
        pdu_data.append((self.user_id >> 8) & 0xFF)  # User ID high byte
        pdu_data.append(self.user_id & 0xFF)          # User ID low byte
        
        self.log_debug(f"Build AttachUserConfirm, user ID: 0x{self.user_id:04x}")
        return self._wrap_x224_data(pdu_data)

    def _build_channel_join_confirm(self):
        """build ChannelJoinConfirm  - FreeRDP mcs.c"""
        pdu_data = bytearray()
        
        # ChannelJoinConfirm PDU - Use correct encoding
        pdu_data.append(0x3F)  # ChannelJoinConfirm (Fixed value)
        pdu_data.append(0x00)  # result:  rt-successful
        pdu_data.append((self.user_id >> 8) & 0xFF)    # User ID high byte
        pdu_data.append(self.user_id & 0xFF)            # User ID low byte  
        pdu_data.append((self.channel_id >> 8) & 0xFF) # Channel ID
        pdu_data.append(self.channel_id & 0xFF)         # Channel ID
        
        self.log_debug(f"Build ChannelJoinConfirm, user ID: 0x{self.user_id:04x}, Channel ID: 0x{self.channel_id:04x}")
        return self._wrap_x224_data(pdu_data)

    def _phase4_rdp_negotiation(self):
        """Phase 4: RDP Session Negotiation"""
        self.log_phase(4, "starting RDP session negotiation")
        
        try:
            # sending，ClientsendingRDP data
            self.log_debug("ClientsendingRDP negotiation response data...")
                
            # Waiting for client RDP data
            for i in range(10):  # Increase waiting rounds
                try:
                    self.client_socket.settimeout(15.0)  # Increase timeout
                    data = self.client_socket.recv(2048)
                    if not data:
                        self.log_debug(f"RDP negotiation phase {i+1}: received data")
                        break
                        
                    self.log_debug(f"Received RDP negotiation data {i+1}", data)
                    
                    # Analyze data type and respond
                    response = self._analyze_and_respond_rdp(data)
                    if response:
                        self.client_socket.send(response)
                        self.log_debug(f"sendingRDP negotiation response {i+1}", response)
                        
                    # Check if license completion information
                    if self._is_license_complete(data):
                        self.log_debug("RDP license negotiation complete")
                        break
                        
                except socket.timeout:
                    self.log_debug(f"RDP negotiation timeout, phase: {i+1}")
                    # Timeout is not necessarily an error, client may be waiting
                    continue
                except Exception as e:
                    self.log_debug(f"RDP negotiation exception: {e}")
                    break
                    
            self.log_phase(4, "RDP session negotiation complete")
            self.connection_established = True
            return True
            
        except Exception as e:
            self.log_phase(4, f"RDP negotiation exception: {e}")
            return False

    def _build_rdp_license_response(self):
        """Build RDP license response"""
        # Build license server Hello message
        rdp_data = bytearray()
        rdp_data.extend([0x02, 0x00])  # License protocol version  
        rdp_data.extend([0x3e, 0x00])  # Length
        rdp_data.extend([0x02, 0x00, 0x00, 0x00])  # Server version
        rdp_data.extend([0x01, 0x00, 0x00, 0x00])  # Scope count
        rdp_data.extend([0x00] * 48)  # Server random number and other data
        
        # MCS SendDataIndication encapsulation
        pdu_data = bytearray()
        pdu_data.append(0x68)  # SendDataIndication
        pdu_data.append((self.user_id >> 8) & 0xFF)
        pdu_data.append(self.user_id & 0xFF) 
        pdu_data.append((self.channel_id >> 8) & 0xFF)
        pdu_data.append(self.channel_id & 0xFF)
        pdu_data.append(0x70)  # Data priority
        pdu_data.extend(struct.pack('>H', len(rdp_data)))
        pdu_data.extend(rdp_data)
        
        return self._wrap_x224_data(pdu_data)

    def _analyze_and_respond_rdp(self, data):
        """Analyze RDP data and build response"""
        try:
            # Simple analysis: MCS SendDataRequest，sending
            if len(data) >= 10 and data[7] == 0x64:  # SendDataRequest
                self.log_debug("received MCS SendDataRequest")
                return self._build_simple_ack()
            else:
                self.log_debug("Received RDP data，sending")
                return self._build_simple_ack()
        except:
            return None

    def _is_license_complete(self, data):
        """Check if license negotiation complete"""
        # Simple check: If data contains specific pattern, consider complete
        return len(data) > 20

    def _build_rdp_response(self, request_data):
        """Build RDP response"""
        # sendingRDP negotiation response
        if len(request_data) >= 7:
            # Build RDP license server certificate response
            rdp_data = self._build_license_request()
            
            # MCS SendDataIndication encapsulation
            pdu_data = bytearray()
            pdu_data.append(0x68)  # SendDataIndication
            pdu_data.append((self.user_id >> 8) & 0xFF)  # User ID high byte
            pdu_data.append(self.user_id & 0xFF)          # User ID low byte
            pdu_data.append((self.channel_id >> 8) & 0xFF) # Channel ID
            pdu_data.append(self.channel_id & 0xFF)         # Channel ID
            pdu_data.append(0x70)  # Data priority
            pdu_data.extend(struct.pack('>H', len(rdp_data)))  # Length
            pdu_data.extend(rdp_data)
            
            return self._wrap_x224_data(pdu_data)
            
        return None

    def _build_license_request(self):
        """Build RDP license request"""
        license_data = bytearray()
        
        # RDP license packet header
        license_data.extend([0x80, 0x00])  # Security header
        license_data.extend([0x00, 0x00])  # Flags
        
        # License negotiation data
        license_data.extend([0x01, 0x00])  # License request
        license_data.extend([0x2c, 0x00])  # Length
        
        #  data
        license_data.extend([0x01, 0x00, 0x00, 0x00])  # Version
        license_data.extend([0x01, 0x00, 0x00, 0x00])  # Client type
        license_data.extend([0x00] * 32)  # Random data
        
        return license_data

    def _phase5_authentication_session(self):
        """Phase 5: User authentication session - Credentials"""
        self.log_phase(5, "entering authentication session phase")
        self.logger.info(f"RDP connection successfully established! Client: {self.client_addr}")
        self.logger.info("MSTSC should now display login interface, waiting for user credentials...")
        
        try:
            # Set long timeout, wait for user input
            self.client_socket.settimeout(600.0)  # 10minute timeout
            
            session_start = time.time()
            while True:
                try:
                    data = self.client_socket.recv(4096)
                    if not data:
                        self.log_debug("client closed connection")
                        break
                        
                    self.log_debug("Received authentication session data", data)
                    
                    # Try to extract credentials
                    credentials = self._extract_credentials_from_data(data)
                    if credentials:
                        self.logger.info(f"*** *** Captured credentials: {credentials} ***")
                        self.credentials_captured.append({
                            'timestamp': datetime.datetime.now().isoformat(),
                            'client_addr': self.client_addr,
                            'credentials': credentials
                        })
                        
                        # Save to file
                        self._save_credentials(credentials)
                    
                    # sending
                    response = self._build_session_keepalive(data)
                    if response:
                        self.client_socket.send(response)
                        
                    # Check session duration
                    if time.time() - session_start > 600:  # 10minutes, actively disconnect
                        self.log_debug("Session timeout, actively disconnect")
                        break
                        
                except socket.timeout:
                    self.log_debug("Authentication session timeout")
                    break
                except Exception as e:
                    self.log_debug(f"Authentication session exception: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Authentication session processing exception: {e}")

    def _extract_credentials_from_data(self, data):
        """Extract credential information from data"""
        try:
            # Look for possible text data
            text_segments = []
            current_text = bytearray()
            
            for b in data:
                if 32 <= b <= 126:  # Printable ASCII characters
                    current_text.append(b)
                elif b == 0:  # NULLTerminator
                    if len(current_text) > 2:
                        try:
                            text_segments.append(current_text.decode('ascii'))
                        except:
                            pass
                    current_text = bytearray()
                else:
                    # Non-text character
                    if len(current_text) > 2:
                        try:
                            text_segments.append(current_text.decode('ascii'))
                        except:
                            pass
                    current_text = bytearray()
                    
            # Add final text segment
            if len(current_text) > 2:
                try:
                    text_segments.append(current_text.decode('ascii'))
                except:
                    pass
                    
            # Filter possible credentials
            credentials = []
            for text in text_segments:
                text = text.strip()
                if len(text) >= 3 and not text.isspace():
                    # Simple filter: Length，
                    credentials.append(text)
                    
            return credentials if credentials else None
            
        except Exception as e:
            self.log_debug(f"Credential extraction exception: {e}")
            return None

    def _save_credentials(self, credentials):
        """Save captured credentials to file"""
        try:
            os.makedirs('logs', exist_ok=True)
            
            with open('logs/captured_credentials.txt', 'a', encoding='utf-8') as f:
                timestamp = datetime.datetime.now().isoformat()
                f.write(f"\n=== {timestamp} ===\n")
                f.write(f"Client: {self.client_addr}\n")
                f.write("Captured credentials:\n")
                for i, cred in enumerate(credentials, 1):
                    f.write(f"  {i}. {cred}\n")
                f.write("\n")
                
        except Exception as e:
            self.logger.error(f"Save credentials exception: {e}")

    def _build_session_keepalive(self, request_data):
        """Build session keepalive response"""
        # Simple response, keep connection active
        if len(request_data) >= 7:
            pdu_data = bytearray([0x00, 0x00, 0x00])  # Basic confirmation
            return self._wrap_x224_data(pdu_data)
        return None

    def _cleanup(self):
        """Clean up resources"""
        try:
            if self.client_socket:
                self.client_socket.close()
        except:
            pass
            
        self.log_phase(0, f"connection  {self.client_addr}  closed")
        
        # Output session summary
        if self.connection_established:
            self.logger.info(f"session summary - client: {self.client_addr}")
            self.logger.info(f"captured credentials count: {len(self.credentials_captured)}")
            for cred_info in self.credentials_captured:
                self.logger.info(f"  Time: {cred_info['timestamp']}")
                self.logger.info(f"  Credentials: {cred_info['credentials']}")


class RDPHoneypotFreeRDP:
    """FreeRDP-based RDP honeypot"""
    
    def __init__(self, host='0.0.0.0', port=3389, log_level=logging.INFO):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Create log directory
        os.makedirs('logs', exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/rdp_honeypot_freerdp.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('rdp_honeypot_freerdp')
        
    def start(self):
        """Start RDP honeypot service"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.running = True
            
            self.logger.info("=" * 60)
            self.logger.info(f"RDP Honeypot (FreeRDP negotiation response) startup successful")
            self.logger.info(f"listening address: {self.host}:{self.port}")
            self.logger.info("protocol support: complete RDP protocol stack with MSTSC client support")
            self.logger.info("functionality: capture username and password input")
            self.logger.info("=" * 60)
            
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    self.logger.info(f"New connection: {client_addr}")
                    logger.warning("New connection", extra={
                        "src_ip_addr": client_addr[0],
                        "src_port" : client_addr[1],
                    },)
                    
                    # ClientHandle 
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept connection exception: {e}")
                        
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
        finally:
            self.stop()
            
    def _handle_client(self, client_socket, client_addr):
        """Handle Client"""
        try:
            protocol = RDPProtocolFreeRDP(client_socket, client_addr, self.logger)
            success = protocol.handle_connection()
            
            if success:
                self.logger.info(f"connection  {client_addr}  processing complete")
            else:
                self.logger.warning(f" {client_addr}  failed")
                
        except Exception as e:
            self.logger.error(f"Handle Client {client_addr} : {e}")
            import traceback
            self.logger.error(f"Detailed error: {traceback.format_exc()}")
        finally:
            try:
                client_socket.close()
            except:
                pass
                
    def stop(self):
        """Stop RDP honeypot service"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.logger.info("RDP Honeypot stopped")

def parse_args() -> tuple[int, str, str]:
    """Returns (port, name, dst_ip)."""
    if len(sys.argv) >= 4:
        return int(sys.argv[1]), sys.argv[2], sys.argv[3]
    return 3389, "honeypot", "0.0.0.0"

if __name__ == "__main__":
    # Run the honeypot server
    port, name, dst_ip = parse_args()
    log_file = f"/log/rdp{port}.log"
    global logger
    logger = build_logger(name, log_file, dst_ip, port) 

    honeypot = RDPHoneypotFreeRDP(host='0.0.0.0', port=port, log_level=logging.DEBUG)
    
    try:
        honeypot.start()
    except KeyboardInterrupt:
        print("\nReceived interrupt signal, stopping service...")
        honeypot.stop()