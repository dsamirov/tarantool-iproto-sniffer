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
usage: main.py [-h] [--iface IFACE] [--port PORT] [--output OUTPUT]

optional arguments:
  -h, --help       show this help message and exit
  --iface IFACE    interface
  --port PORT      tarantool port
  --output OUTPUT  output filename

$ sudo ./venv/bin/python main.py --iface lo --output result.file
```

# Examples

## Execute dump file to another tarantool instance

Required [jq](https://stedolan.github.io/jq/)

```
$ jq -M .payload.hex < result.file | sed 's/"//g' | xxd -r -p | nc localhost 3301
```
