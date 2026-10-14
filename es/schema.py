#!/usr/bin/env python3
"""In cấu trúc khoá (tên trường + kiểu, KHÔNG in giá trị) của mẫu sự kiện eslogger mà macsentry-es đã lưu,
để đối chiếu bộ đọc trong es/main.swift với định dạng thật. Chạy: sudo python3 -I es/schema.py"""
import glob, json, os, sys

d = sys.argv[1] if len(sys.argv) > 1 else "/var/db/macsentry/es_samples"
SKIP = {"stat", "audit_token", "parent_audit_token", "responsible_audit_token", "cdhash", "thread"}


def walk(v, ind, depth):
    if depth > 6:
        return
    if isinstance(v, dict):
        for k in sorted(v):
            x = v[k]
            kind = type(x).__name__ if x is not None else "null"
            if k in SKIP and isinstance(x, dict):
                print(f"{ind}{k}: dict(…)")
                continue
            print(f"{ind}{k}: {kind}")
            walk(x, ind + "  ", depth + 1)
    elif isinstance(v, list) and v and isinstance(v[0], dict):
        print(f"{ind}[0]:")
        walk(v[0], ind + "  ", depth + 1)


files = sorted(glob.glob(os.path.join(d, "*.json")))
print("Mẫu có:", ", ".join(os.path.basename(f)[:-5] for f in files) or "(chưa có)")
for f in files:
    name = os.path.basename(f)[:-5]
    msg = json.load(open(f))
    print(f"\n== {name} (version {msg.get('version')}, schema {msg.get('schema_version')})")
    walk(msg.get("event", {}).get(name, {}), "  ", 0)
