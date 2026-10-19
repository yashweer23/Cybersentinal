import hashlib
import json


def fingerprint(rule_id, entity, anchor_event_id):
    canonical = json.dumps(
        ["detection-v1", rule_id, list(entity), anchor_event_id],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
