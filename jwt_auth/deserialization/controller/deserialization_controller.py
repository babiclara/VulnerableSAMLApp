from flask import Blueprint, request, Response
from deserialization.util.deserialization_utils import decode_base64, deserialize_unsafe, deserialize_safe, SecurityError

deserialization_bp = Blueprint("deserialization", __name__)

@deserialization_bp.route("/api/deserialize/vulnerable", methods=["POST"])
def deserialize_vulnerable():
    raw = decode_base64(request.get_data(as_text=True))
    obj = deserialize_unsafe(raw)
    return Response(str(obj), status=200, mimetype="text/plain")

@deserialization_bp.route("/api/deserialize/secure", methods=["POST"])
def deserialize_secure():
    try:
        raw = decode_base64(request.get_data(as_text=True))
        obj = deserialize_safe(raw)
        return Response(str(obj), status=200, mimetype="text/plain")
    except SecurityError as e:
        return Response(str(e), status=403, mimetype="text/plain")
    except Exception as e:
        return Response(f"[ERROR] {e}", status=400, mimetype="text/plain")