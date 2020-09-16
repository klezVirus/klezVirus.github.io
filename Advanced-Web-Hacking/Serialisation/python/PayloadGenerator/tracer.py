import re
import sys

import jsonpickle


def trace(frame, event, arg):
    if event != 'call':
        return
    c_object = frame.f_code
    func_name = c_object.co_name
    if not re.search(r"load", func_name):
        return
    func_name_line_no = frame.f_lineno
    func_filename = c_object.co_filename
    caller = frame.f_back
    caller_line_no = caller.f_lineno
    caller_filename = caller.f_code.co_filename
    print('Call to {0} on line {1} of {2} from line {3} of {4}'.format(
        func_name, func_name_line_no, func_filename,
        caller_line_no, caller_filename))


with open("payload.json", "r") as payload:
    sys.settrace(trace)
    jsonpickle.decode(payload.read())
