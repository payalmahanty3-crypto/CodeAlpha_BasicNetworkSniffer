"""
=============================================================
  Basic Network Sniffer — CodeAlpha Cybersecurity Internship
  Task 1: Capture & Analyze Network Packets
  Usage: python network_sniffer.py
=============================================================
"""

import socket
import struct
import textwrap
import datetime
import json
import os

# ─────────────────────────────────────────────────────────────
# PACKET PARSERS
# ─────────────────────────────────────────────────────────────

def parse_ethernet(data):
    dest_mac = format_mac(data[:6])
    src_mac  = format_mac(data[6:12])
    proto    = struct.unpack('!H', data[12:14])[0]
    return dest_mac, src_mac, proto, data[14:]

def format_mac(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes).upper()

def format_ip(addr):
    return '.'.join(map(str, addr))

def parse_ipv4(data):
    version_ihl = data[0]
    ihl         = (version_ihl & 0xF) * 4
    ttl         = data[8]
    proto       = data[9]
    src         = format_ip(data[12:16])
    dst         = format_ip(data[16:20])
    return src, dst, proto, ttl, data[ihl:]

def parse_tcp(data):
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    seq      = struct.unpack('!L', data[4:8])[0]
    ack      = struct.unpack('!L', data[8:12])[0]
    offset   = (data[12] >> 4) * 4
    flags    = data[13]
    flag_str = ''.join([
        'SYN ' if flags & 0x02 else '',
        'ACK ' if flags & 0x10 else '',
        'FIN ' if flags & 0x01 else '',
        'RST ' if flags & 0x04 else '',
        'PSH ' if flags & 0x08 else '',
        'URG ' if flags & 0x20 else '',
    ]).strip()
    payload  = data[offset:]
    return src_port, dst_port, seq, ack, flag_str, payload

def parse_udp(data):
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    length   = struct.unpack('!H', data[4:6])[0]
    payload  = data[8:]
    return src_port, dst_port, length, payload

def parse_icmp(data):
    icmp_type = data[0]
    code      = data[1]
    checksum  = struct.unpack('!H', data[2:4])[0]
    types = {0:'Echo Reply', 3:'Dest Unreachable', 8:'Echo Request',
             11:'Time Exceeded', 5:'Redirect'}
    type_str = types.get(icmp_type, f'Type {icmp_type}')
    return type_str, code, checksum, data[4:]

def format_payload(data, max_bytes=64):
    if not data:
        return "(no payload)"
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:max_bytes])
    hex_view  = ' '.join(f'{b:02x}' for b in data[:max_bytes])
    suffix    = f'... (+{len(data)-max_bytes} bytes)' if len(data) > max_bytes else ''
    return f"HEX : {hex_view}{suffix}\n         ASCII: {printable}{suffix}"

def get_protocol_name(num):
    return {1:'ICMP', 6:'TCP', 17:'UDP'}.get(num, f'OTHER({num})')

def get_service(port):
    services = {
        80:'HTTP', 443:'HTTPS', 22:'SSH', 21:'FTP', 25:'SMTP',
        53:'DNS', 110:'POP3', 143:'IMAP', 3306:'MySQL', 3389:'RDP',
        8080:'HTTP-Alt', 23:'Telnet', 445:'SMB', 137:'NetBIOS',
    }
    return services.get(port, '')

# ─────────────────────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────────────────────

PROTO_COLOR = {'TCP':'\033[94m', 'UDP':'\033[92m', 'ICMP':'\033[93m', 'OTHER':'\033[90m'}
RESET = '\033[0m'
BOLD  = '\033[1m'

def print_banner():
    print(f"{BOLD}")
    print("=" * 65)
    print("   BASIC NETWORK SNIFFER")
    print("   CodeAlpha Cybersecurity Internship — Task 1")
    print("   Captures & Analyzes Network Packets in Real Time")
    print("=" * 65)
    print(f"{RESET}")

def print_packet(count, timestamp, src_ip, dst_ip, proto_name,
                 src_port=None, dst_port=None, flags='',
                 icmp_type='', payload=b'', ttl=0):

    color  = PROTO_COLOR.get(proto_name, PROTO_COLOR['OTHER'])
    svc_s  = get_service(src_port) if src_port else ''
    svc_d  = get_service(dst_port) if dst_port else ''
    port_s = f":{src_port}" + (f"({svc_s})" if svc_s else '') if src_port else ''
    port_d = f":{dst_port}" + (f"({svc_d})" if svc_d else '') if dst_port else ''

    print(f"{color}{BOLD}[#{count:04d}] {timestamp}  {proto_name}{RESET}")
    print(f"  SRC  : {src_ip}{port_s}")
    print(f"  DST  : {dst_ip}{port_d}")
    if flags:      print(f"  FLAGS: {flags}")
    if icmp_type:  print(f"  ICMP : {icmp_type}")
    if ttl:        print(f"  TTL  : {ttl}")
    print(f"  DATA : {format_payload(payload)}")
    print("-" * 65)

# ─────────────────────────────────────────────────────────────
# LOGGER
# ─────────────────────────────────────────────────────────────

captured = []

def log_packet(entry):
    captured.append(entry)

def save_log(filename='sniffer_log.json'):
    summary = {
        'session': {
            'captured': len(captured),
            'timestamp': datetime.datetime.now().isoformat(),
        },
        'protocol_breakdown': {
            'TCP':  sum(1 for p in captured if p['protocol']=='TCP'),
            'UDP':  sum(1 for p in captured if p['protocol']=='UDP'),
            'ICMP': sum(1 for p in captured if p['protocol']=='ICMP'),
        },
        'top_services': {},
        'packets': captured,
    }
    services = {}
    for p in captured:
        svc = p.get('service','')
        if svc:
            services[svc] = services.get(svc,0)+1
    summary['top_services'] = dict(sorted(services.items(), key=lambda x:-x[1])[:5])

    with open(filename,'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*65}")
    print(f"  SESSION COMPLETE")
    print(f"{'='*65}")
    print(f"  Packets captured : {len(captured)}")
    print(f"  TCP  : {summary['protocol_breakdown']['TCP']}")
    print(f"  UDP  : {summary['protocol_breakdown']['UDP']}")
    print(f"  ICMP : {summary['protocol_breakdown']['ICMP']}")
    if summary['top_services']:
        print(f"\n  Top services detected:")
        for svc,cnt in summary['top_services'].items():
            print(f"    {svc:<12} {cnt} packet(s)")
    print(f"\n  Log saved → {filename}")
    print(f"{'='*65}")

# ─────────────────────────────────────────────────────────────
# MAIN SNIFFER LOOP
# ─────────────────────────────────────────────────────────────

def sniff(max_packets=50):
    print_banner()

    try:
        # Windows uses AF_INET + IPPROTO_IP with SOCK_RAW
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((socket.gethostbyname(socket.gethostname()), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Enable promiscuous mode on Windows
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        windows_mode = True
    except (AttributeError, OSError):
        try:
            # Linux raw socket
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            windows_mode = False
        except PermissionError:
            print("\n[ERROR] Run as Administrator (Windows) or sudo (Linux)")
            print("  Windows: Right-click PowerShell → Run as Administrator")
            print("  Linux:   sudo python network_sniffer.py\n")
            return

    print(f"  [*] Sniffing started — capturing {max_packets} packets")
    print(f"  [*] Press Ctrl+C to stop early\n")
    print("-" * 65)

    count = 0
    try:
        while count < max_packets:
            raw, _ = conn.recvfrom(65535)
            ts     = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]

            try:
                if windows_mode:
                    # Raw IP packet on Windows
                    src_ip, dst_ip, proto_num, ttl, payload = parse_ipv4(raw)
                    proto_name = get_protocol_name(proto_num)
                    entry = {
                        'id': count+1, 'timestamp': ts,
                        'src_ip': src_ip, 'dst_ip': dst_ip,
                        'protocol': proto_name, 'ttl': ttl,
                        'src_port': None, 'dst_port': None,
                        'flags': '', 'service': '', 'payload_bytes': len(payload),
                    }
                    if proto_num == 6:    # TCP
                        sp,dp,seq,ack,flags,pload = parse_tcp(payload)
                        entry.update({'src_port':sp,'dst_port':dp,'flags':flags,
                                      'service': get_service(dp) or get_service(sp)})
                        print_packet(count+1, ts, src_ip, dst_ip, 'TCP',
                                     sp, dp, flags=flags, payload=pload, ttl=ttl)
                    elif proto_num == 17: # UDP
                        sp,dp,length,pload = parse_udp(payload)
                        entry.update({'src_port':sp,'dst_port':dp,
                                      'service': get_service(dp) or get_service(sp)})
                        print_packet(count+1, ts, src_ip, dst_ip, 'UDP',
                                     sp, dp, payload=pload, ttl=ttl)
                    elif proto_num == 1:  # ICMP
                        itype,code,_,pload = parse_icmp(payload)
                        entry.update({'icmp_type': itype})
                        print_packet(count+1, ts, src_ip, dst_ip, 'ICMP',
                                     icmp_type=itype, payload=pload, ttl=ttl)
                    else:
                        print_packet(count+1, ts, src_ip, dst_ip, proto_name,
                                     payload=payload, ttl=ttl)

                else:
                    # Ethernet frame on Linux
                    dest_mac, src_mac, eth_proto, ip_data = parse_ethernet(raw)
                    if eth_proto == 0x0800:
                        src_ip,dst_ip,proto_num,ttl,payload = parse_ipv4(ip_data)
                        proto_name = get_protocol_name(proto_num)
                        entry = {
                            'id': count+1, 'timestamp': ts,
                            'src_ip': src_ip, 'dst_ip': dst_ip,
                            'protocol': proto_name, 'ttl': ttl,
                            'src_port': None, 'dst_port': None,
                            'flags':'', 'service':'', 'payload_bytes': len(payload),
                        }
                        if proto_num == 6:
                            sp,dp,seq,ack,flags,pload = parse_tcp(payload)
                            entry.update({'src_port':sp,'dst_port':dp,'flags':flags,
                                          'service': get_service(dp) or get_service(sp)})
                            print_packet(count+1,ts,src_ip,dst_ip,'TCP',
                                         sp,dp,flags=flags,payload=pload,ttl=ttl)
                        elif proto_num == 17:
                            sp,dp,length,pload = parse_udp(payload)
                            entry.update({'src_port':sp,'dst_port':dp,
                                          'service': get_service(dp) or get_service(sp)})
                            print_packet(count+1,ts,src_ip,dst_ip,'UDP',
                                         sp,dp,payload=pload,ttl=ttl)
                        elif proto_num == 1:
                            itype,code,_,pload = parse_icmp(payload)
                            entry.update({'icmp_type':itype})
                            print_packet(count+1,ts,src_ip,dst_ip,'ICMP',
                                         icmp_type=itype,payload=pload,ttl=ttl)
                        else:
                            entry = {'id':count+1,'timestamp':ts,'src_ip':'?',
                                     'dst_ip':'?','protocol':'OTHER','ttl':0,
                                     'src_port':None,'dst_port':None,'flags':'',
                                     'service':'','payload_bytes':0}
                            print_packet(count+1,ts,'?','?','OTHER',payload=raw)
                    else:
                        continue

                log_packet(entry)
                count += 1

            except Exception:
                continue

    except KeyboardInterrupt:
        print("\n\n  [!] Stopped by user")
    finally:
        if windows_mode:
            try:
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass
        conn.close()
        if captured:
            save_log()


if __name__ == '__main__':
    sniff(max_packets=50)
