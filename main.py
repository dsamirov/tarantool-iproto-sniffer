from scapy.all import *

import argparse
import msgpack
import json
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
				"hex": payload2hex(payload),
				"iproto": [],
			},
		}

		# Батчинг

		cursor = 0
		while True:
			item = {}
			item_bsize = msgpack.unpackb(payload[cursor:5], raw=False)

			header_begin = cursor + payload[cursor:].find(MP_MAP_HEADER)
			body_begin = header_begin + 1 + payload[header_begin+1:].find(MP_MAP_HEADER)

			next_mp_header = payload[body_begin+1:].find(MP_MAP_HEADER)

			if header_begin == -1 or body_begin == -1:
				break

			body_end = header_begin + item_bsize

			cursor = body_end

			header = payload[header_begin:body_begin]
			if next_mp_header == -1:
				body = payload[body_begin:body_end]
			else:
				body = payload[body_begin:body_end-5]

			try:
				iproto_header = msgpack.unpackb(header, raw=False)
				item["header"] = {
					"REQUEST_ID": iproto_header[1],
					"COMMAND": IPROTO_COMMAND_NAMES[iproto_header[0]],
				}
			except:
				item["header_hex"] = payload2hex(payload[header_begin:body_begin])
				item["header_error"] = str(sys.exc_info()[0])

			try:
				iproto_body = msgpack.unpackb(body, raw=True)
				item["body"] = get_iproto_payload(iproto_body)
			except:
				item["body_hex"] = payload2hex(payload[body_begin:body_end])
				item["body_error"] = str(sys.exc_info()[0])

			request["payload"]["iproto"].append(item)

			if next_mp_header == -1:
				break

		fout.write(json.dumps(request, cls=Base64Encoder) + "\n")
		if flush:
			fout.flush()

	return iproto_parse

parser = argparse.ArgumentParser()
parser.add_argument("--iface", help="interface", default="lo")
parser.add_argument("--port", help="tarantool port", default="3301")
parser.add_argument("--output", help="output filename", default="/dev/stdout")

args = parser.parse_args()

fout = open(args.output, "w")

sniff(iface=args.iface, filter="dst port " + args.port, prn=parse_callback(fout, True))
