import base64
import pickle
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deserialization.model.user_profile import UserProfile
from deserialization.model.evil_payload import EvilPayload

def to_base64(obj):
    return base64.b64encode(pickle.dumps(obj)).decode("utf-8")

if __name__ == "__main__":
    print("UserProfile (safe)")
    print(to_base64(UserProfile("lara", "lara@example.com", 42)))

    print("\n EvilPayload (malicious)")
    print(to_base64(EvilPayload()))