# -*- coding: utf-8 -*-
"""XHS signing helper — called by xiaohongshu.mjs via child_process.
Usage: echo '{"uri":"...","cookies":"...","method":"GET","params":{}}' | python xhs_sign_helper.py
Output: JSON with x-s, x-t, x-s-common, x-b3-traceid headers
"""
import hashlib
import json
import sys

from xhshow import Xhshow
from xhshow.core.crypto import CryptoProcessor


_original_build_payload_array = CryptoProcessor.build_payload_array


def _patched_build_payload_array(self, hex_parameter, a1_value, app_identifier="xhs-pc-web", string_param="", timestamp=None, sign_state=None):
    payload = _original_build_payload_array(self, hex_parameter, a1_value, app_identifier, string_param, timestamp, sign_state)
    if "{" not in string_param:
        correct_md5_hex = hashlib.md5(string_param.encode("utf-8")).hexdigest()
        correct_md5_bytes = [int(correct_md5_hex[i:i + 2], 16) for i in range(0, 32, 2)]
        seed_byte = payload[4]
        ts_bytes = payload[8:16]
        correct_a3_hash = self._custom_hash_v2(list(ts_bytes) + correct_md5_bytes)
        for i in range(16):
            payload[128 + i] = correct_a3_hash[i] ^ seed_byte
    return payload


CryptoProcessor.build_payload_array = _patched_build_payload_array


def main():
    raw = sys.stdin.read()
    req = json.loads(raw)
    uri = req["uri"]
    cookies = req.get("cookies", "")
    method = req.get("method", "GET").upper()
    params = req.get("params")
    payload = req.get("payload")

    client = Xhshow()

    if method == "POST":
        headers = client.sign_headers_post(uri, cookies, payload=payload)
    else:
        headers = client.sign_headers_get(uri, cookies, params=params)

    print(json.dumps(headers, ensure_ascii=False))


if __name__ == "__main__":
    main()
