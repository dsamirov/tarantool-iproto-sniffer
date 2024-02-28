# Info

Supported tarantool commands:

* INSERT
* REPLACE
* CALL

# Install

```
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

# Usage

```
$ sudo ./venv/bin/python main.py -h
usage: main.py [-h] [-i IFACE] [--from-pcap FROM_PCAP] [--filter FILTER] [--output OUTPUT]

options:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        interface
  --from-pcap FROM_PCAP
                        from pcap file
  --filter FILTER       filter to pcap file (ex. port 3301)
  --output OUTPUT       output filename

$ sudo ./venv/bin/python main.py --iface lo --output result.file
```

# Examples

## Read from pcap

Filter is the same as "tcpdump filter", so you may:

`src port 3301` or `port 3301 and dst host 127.0.0.1` and so on.

```
$ python3 main.py --from-pcap traffic.pcap --filter "port 3301"
```

## Sniff in realtime

```
$ python3 main.py --iface eth0 --filter "port 3301"
```

## Execute dump file to another tarantool instance

Required [jq](https://stedolan.github.io/jq/)

```
$ jq -M .payload.hex < result.file | sed 's/"//g' | xxd -r -p | nc localhost 3301
```
