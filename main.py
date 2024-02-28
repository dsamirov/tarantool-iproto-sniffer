from scapy.all import *

import argparse
import msgpack
import json
import sys
from io import BytesIO
from base64 import b64encode

MP_MAP_HEADER = 0x82

class IPROTO_KEY:
	SYNC = 0x01
	SCHEMA_ID = 0x05
	SPACE_ID = 0x10
	TUPLE = 0x21
	FUNCTION_NAME = 0x22
	USERNAME = 0x23
	EXPR = 0x27
	OPS = 0x28
	DATA = 0x30
	ERROR = 0x31

class IPROTO_COMMAND:
	OK = 0x00
	SELECT = 0x01
	INSERT = 0x02
	REPLACE = 0x03
	UPDATE = 0x04
	DELETE = 0x05
	CALL_16 = 0x06
	AUTH = 0x07
	EVAL = 0x08
	UPSERT = 0x09
	CALL = 0x0a

	# admin commands
	PING = 0x40
	JOIN = 0x41
	SUBSCRIBE = 0x42
	REQUEST_VOTE = 0x43

IPROTO_KEY_NAMES = {value: name for name, value in vars(IPROTO_KEY).items() if name.isupper()}
IPROTO_COMMAND_NAMES = {value: name for name, value in vars(IPROTO_COMMAND).items() if name.isupper()}

def get_iproto_payload(body):
	payload = {}

	for name, value in vars(IPROTO_KEY).items():
		if value not in body:
			continue

		payload[name] = body[value]

	return payload

class Base64Encoder(json.JSONEncoder):
	def default(self, o):
		if isinstance(o, bytes):
			try:
				return o.decode('utf-8')
			except:
				return " ".join(["{:02x}".format(x) for x in o])
		return json.JSONEncoder.default(self, o)

def payload2hex(payload):
	return ' '.join( '{:02x}'.format(x) for x in payload )

def parse_callback(fout, flush):
	def iproto_parse(pkt):
		if not hasattr(pkt.getlayer("Raw"), "load"):
			return

		layer_ip = pkt.getlayer("IP")
		layer_tcp = pkt.getlayer("TCP")
		if not layer_tcp:
			return

		payload = pkt.getlayer("Raw").load

		request = {
			"headers": {
				"ip": {
					"id": layer_ip.id,
					"src": layer_ip.src,
					"dst": layer_ip.dst,
				},
				"tcp": {
					"sport": layer_tcp.sport,
					"dport": layer_tcp.dport,
					"seq": layer_tcp.seq,
					"ack": layer_tcp.ack,
					"window": layer_tcp.window,
				},
			},
			"payload": {
				# "hex": payload2hex(payload),
				"iproto": [],
			},
		}

		# Батчинг

		stream = BytesIO(payload)
		msgs = [ u for u in msgpack.Unpacker(stream, raw=False) ]

		# record is (size, header, body)
		for i in range(0, len(msgs), 3):
			item_bsize = msgs[i]
			header = msgs[i+1]
			body = msgs[i+2]

			item = {}
			item["header"] = {
				"SYNC_ID": header[1],
				"COMMAND": IPROTO_COMMAND_NAMES[header[0]],
			}
			item["body"] = get_iproto_payload(body)
			request["payload"]["iproto"].append(item)

		fout.write(json.dumps(request, cls=Base64Encoder) + "\n")
		if flush:
			fout.flush()

	return iproto_parse

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--iface", help="interface", default="lo")
parser.add_argument("--from-pcap", help="from pcap file")
parser.add_argument("--filter", help="filter to pcap file (ex. port 3301)")
parser.add_argument("--output", help="output filename", default="/dev/stdout")

args = parser.parse_args()
fout = open(args.output, "w")

if args.from_pcap:
	sniff(offline=args.from_pcap, filter=args.filter or "", prn=parse_callback(fout, True))
else:
	sniff(interface=args.iface, filter=args.filter or "", prn=parse_callback(fout, True))
