import socket
import struct
import sys

CHUNK = 65565

def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()

def get_ip(addr):
	return '.'.join(map(str, addr))


# Unpacks the Ethernet Header
def ethernet_head(raw_data):
	
	dest, src, protocol = struct.unpack('! 6s 6s H', raw_data[:14])
	
	dest_mac = get_mac_addr(dest)
	src_mac = get_mac_addr(src)
	proto = socket.htons(protocol)
	data = raw_data[14:]
	
	return dest_mac, src_mac, proto, data


# Unpacks teh IPv4 Packet
def ipv4_head(data):
	
	version_header_len = data[0]
	version = version_header_len >> 4
	header_len = (version_header_len & 15) * 4
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	
	return version, header_len, ttl, proto, get_ip(src), get_ip(target), data[header_len:]


# Unpacks the ICMP packet
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]


# Unpacks the TCP packet segment
def tcp_packet_segment(data):
	(src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = 	(offset_reserved_flags & 32) * 5
	flag_ack = 	(offset_reserved_flags & 16) * 4
	flag_psh = 	(offset_reserved_flags & 8) * 3
	flag_rst = 	(offset_reserved_flags & 4) * 2
	flag_syn = 	(offset_reserved_flags & 2) * 1
	flag_fin = 	offset_reserved_flags & 1

	return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[8:]


def main():
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		raw_data, addr = s.recvfrom(CHUNK)
		dest_mac, src_mac,eth_proto, data = ethernet_head(raw_data)

		print("\nEthernet Header:")
		print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

		# IPv4 Protocol = 8
		if eth_proto == 8:
			version, header_len, ttl, proto, src, target, data = ipv4_head(data)
			print("\tIPv4:")
			print(f"\t\tVersion: {version}, Header Length: {header_len}, TTL: {ttl}")
			print(f"\t\tProto: {proto}, Source: {src}, Destination: {target}")

			# ICMP
			if proto == 1:
				icmp_type, code, checksum, data = icmp_packet(data)
				print("\tICMP Packet:")
				print(f"\t\tICMP Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
				print(f"\t\tData: {data}")

			# TCP
			elif proto == 6:
				src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet_segment(data)
				print("\tTCP Packet:")
				print(f"\t\tSource Port: {src_port}, Destination Port: {dest_port}")
				print(f"\t\tSequence: {sequence}, Acknowledgement: {ack}")
				print(f"\t\tflags:")
				print(f"\t\t\tURG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")
				print(f"\t\tData: {data}")

			# UDP
			elif proto == 17:
				src_port, dest_port, size, data = udp_packet(data)
				print("\tUDP Packet:")
				print(f"\t\tSource Port: {src_port}, Destination Port: {dest_port}, Size: {size}")
				print(f"\t\tData: {data}")

			# Other
			else:
				print(f"\tData: {data}")

		else:
			print(f"Data: {data}")


main()