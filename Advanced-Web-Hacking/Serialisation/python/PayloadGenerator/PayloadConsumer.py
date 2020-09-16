import _pickle
import sys
import yaml
import jsonpickle

if sys.argv[1] == "b":
    with open("payload.bin", "rb") as payload:
        _pickle.loads(payload.read())
elif sys.argv[1] == "y":
    with open("payload.yml", "r") as payload:
        if float(yaml.__version__) <= 5.1:
            yaml.load(payload)
        else:
            yaml.unsafe_load(payload)
elif sys.argv[1] == "j":
    with open("payload.json", "r") as payload:
        jsonpickle.decode(payload.read())