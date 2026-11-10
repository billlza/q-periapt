"""Owned loopback fixture server; only public browser outputs are captured."""
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import threading


@contextmanager
def serving(web: Path, captures: Path):
    for phase in ('creation', 'late'):
        (captures / phase).mkdir(parents=True)

    class Handler(SimpleHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(10)
            super().setup()

        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(web), **kwargs)

        def log_message(self, _format, *_args):
            # HTTP diagnostics are represented by status and the browser collector.
            pass

        def end_headers(self):
            self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
            self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
            self.send_header('Cache-Control', 'no-store')
            super().end_headers()

        def do_POST(self):
            match = re.fullmatch(r'/(creation|late)/capture/([A-Za-z0-9.-]+\.(?:bin|json))', self.path)
            raw_length = self.headers.get('Content-Length', '')
            if (not match or not raw_length.isdecimal() or not 0 < int(raw_length) <= 1048576
                    or self.headers.get('Origin') != origin):
                self.send_error(400); return
            target = captures / match[1] / match[2]
            body = self.rfile.read(int(raw_length))
            if len(body) != int(raw_length):
                self.send_error(400); return
            try:
                with target.open('xb') as stream:
                    stream.write(body)
            except FileExistsError:
                self.send_error(409); return
            self.send_response(201); self.end_headers(); self.wfile.write(b'captured')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = False
    origin = f'http://127.0.0.1:{server.server_port}'
    worker = threading.Thread(target=server.serve_forever, name='continuity-browser-fixture')
    worker.start()
    try:
        yield origin
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=5)
        if worker.is_alive():
            raise RuntimeError('browser fixture server did not stop')
