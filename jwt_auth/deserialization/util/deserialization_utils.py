import base64
import io
import pickle

ALLOWED_CLASSES = {
    ("deserialization.model.user_profile", "UserProfile"),
    ("builtins", "str"),
    ("builtins", "int"),
}

MAX_BYTES = 50000

class SecurityError(Exception):
    pass

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in ALLOWED_CLASSES:
            raise SecurityError(
                f"[SECURITY] Deserialization blocked: class {module}.{name} is not on the allowlist."
            )
        return super().find_class(module, name)

def decode_base64(data):
    return base64.b64decode(data.strip())

def deserialize_unsafe(data):
    return pickle.loads(data)

def deserialize_safe(data):
    if len(data) > MAX_BYTES:
        raise SecurityError(f"[SECURITY] Payload too large: {len(data)} bytes.")
    return SafeUnpickler(io.BytesIO(data)).load()