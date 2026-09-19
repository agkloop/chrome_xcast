#!/usr/bin/env python3
"""Casts one URL through the installed, sandboxed helper, speaking the same
native-messaging protocol as the extension. Usage: nm_cast.py <tv-ip> <url> <referer>"""
import json, os, queue, struct, subprocess, sys, threading, time

tv_ip, url, referer = sys.argv[1:4]
wrapper = os.path.expanduser('~/Library/Application Support/XCast/xcast-host-sandboxed')
manifest = os.path.expanduser('~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.xcast.host.json')
origin = json.load(open(manifest))['allowed_origins'][0]
p = subprocess.Popen([wrapper, origin], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
q = queue.Queue()

def reader():
    while True:
        h = p.stdout.read(4)
        if len(h) < 4:
            break
        q.put(json.loads(p.stdout.read(struct.unpack('=I', h)[0])))
threading.Thread(target=reader, daemon=True).start()

def call(msg, timeout=80):
    b = json.dumps(msg).encode()
    p.stdin.write(struct.pack('=I', len(b)) + b)
    p.stdin.flush()
    end = time.time() + timeout
    while time.time() < end:
        try:
            m = q.get(timeout=1)
        except queue.Empty:
            continue
        if m.get('id') == msg['id']:
            return m
    return {'ok': False, 'error': 'no answer'}

def watch(seconds):
    out, end = [], time.time() + seconds
    while time.time() < end:
        try:
            m = q.get(timeout=1)
        except queue.Empty:
            continue
        if m.get('type') == 'media':
            out.append((m['state'], round(m.get('currentTime', 0), 1), m.get('idleReason') or ''))
    return out

tv = {'host': tv_ip, 'port': 8009}
media = {'url': url, 'referer': referer, 'userAgent': 'Mozilla/5.0 XCast-lab', 'title': 'XCast test lab'}
r = call({'id': 1, 'type': 'cast', 'device': tv, 'media': media})
print('cast                 ->', r.get('code') or {k: r[k] for k in ('mode', 'contentType') if k in r}, r.get('error', ''))
if r.get('code') == 'LOCAL_STREAM':
    r = call({'id': 2, 'type': 'cast', 'device': tv, 'media': {**media, 'allowLocal': True}})
    print('cast, confirmed      ->', r.get('code') or {k: r[k] for k in ('mode', 'contentType') if k in r}, r.get('error', ''))
if r.get('ok'):
    print('TV, first 14 s       ->', watch(14)[-4:])
    print('seek to 60 s         ->', call({'id': 3, 'type': 'control', 'action': 'seek', 'value': 60}, 15).get('ok'))
    print('TV after seek        ->', watch(8)[-3:])
    print('stop                 ->', call({'id': 4, 'type': 'control', 'action': 'stop', 'value': 0}, 15).get('ok'))
p.stdin.close()
p.wait(timeout=5)
