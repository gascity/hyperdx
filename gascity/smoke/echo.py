# Header/body capture server for the HyperDX smoke test. Answers every request
# with 200 and a tiny ClickHouse-ish body; appends one JSON line per request to
# /captures/requests.jsonl (method, path, headers, body prefix).
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT = '/captures/requests.jsonl'

class H(BaseHTTPRequestHandler):
    def _handle(self):
        if 'chunked' in (self.headers.get('transfer-encoding') or '').lower():
            body = b''
            while True:
                size = int(self.rfile.readline().strip().split(b';')[0] or b'0', 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            n = int(self.headers.get('content-length') or 0)
            body = self.rfile.read(n) if n else b''
        rec = {'method': self.command, 'path': self.path,
               'headers': {k.lower(): v for k, v in self.headers.items()},
               'body_prefix': body[:1048576].decode('latin-1')}
        with open(OUT, 'a') as f:
            f.write(json.dumps(rec) + '\n')
        payload = b'{"meta":[{"name":"1","type":"UInt8"}],"data":[{"1":1}],"rows":1}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    do_GET = do_POST = do_PUT = do_DELETE = _handle
    def log_message(self, *a):
        pass

ThreadingHTTPServer(('0.0.0.0', int(sys.argv[1]) if len(sys.argv) > 1 else 8123), H).serve_forever()
