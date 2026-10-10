"""Capture Cargo alias metadata using synthetic local dependencies only.

Usage: python3 SCRIPT FRESH_OUTPUT REAL_TOOLCHAIN_DIRECTORY

The loopback endpoint deliberately rejects the captured request with HTTP 403.
An explicit denying proxy blocks any accidentally selected external registry.
No real registry credentials are read from the isolated CARGO_HOME.
"""
from pathlib import Path
import gzip, hashlib, http.server, io, json, os, struct, subprocess, sys, tarfile, threading

out = Path(sys.argv[1]).resolve()
out.mkdir()
tc = Path(sys.argv[2]).resolve()
home = out / 'cargo-home'
home.mkdir()
project = out / 'fixture'
(project / 'src').mkdir(parents=True)
readme = '# Cargo alias wire fixture\n\nSynthetic dependencies; local capture only.\n'
manifest = '''[workspace]

[package]
name = "registry-alias-fixture"
version = "0.0.0"
edition = "2021"
description = "Local Cargo alias serialization fixture"
license = "MIT"
readme = "README.md"
repository = "https://example.invalid/fixture"

[dependencies]
plain = "=1.0.0"
normal-alias = { package = "normal-original", version = "=1.0.0" }
optional-alias = { package = "optional-original", version = "=1.0.0", optional = true, default-features = false, features = ["extra"] }
same-name = { package = "same-name", version = "=1.0.0" }

[dev-dependencies]
dev-alias = { package = "dev-original", version = "=1.0.0" }

[build-dependencies]
build-alias = { package = "build-original", version = "=1.0.0" }

[target.'cfg(unix)'.dependencies]
target-alias = { package = "target-original", version = "=1.0.0" }

[features]
maintenance = ["dep:optional-alias"]
'''
(project / 'Cargo.toml').write_text(manifest)
(project / 'README.md').write_text(readme)
(project / 'src/lib.rs').write_text('pub fn fixture() {}\n')
archives, records = {}, {}
def pack(name):
    members = {'Cargo.toml': f'[package]\nname="{name}"\nversion="1.0.0"\nedition="2021"\n[features]\nextra=[]\n', 'src/lib.rs': 'pub fn fixture() {}\n'}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as archive:
        for path, text in members.items():
            b = text.encode(); info = tarfile.TarInfo(f'{name}-1.0.0/{path}'); info.size = len(b); archive.addfile(info, io.BytesIO(b))
    return gzip.compress(buf.getvalue(), mtime=0)
for name in ('plain', 'normal-original', 'optional-original', 'same-name', 'dev-original', 'build-original', 'target-original'):
    archives[name] = pack(name)
    records[name] = json.dumps({'name': name, 'vers': '1.0.0', 'deps': [], 'cksum': hashlib.sha256(archives[name]).hexdigest(), 'features': {'extra': []}, 'yanked': False}).encode() + b'\n'
requests = []
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def respond(self, status, body):
        self.send_response(status); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_CONNECT(self):
        requests.append(['DENIED_CONNECT', self.path]); self.respond(403, b'no external access')
    def do_GET(self):
        requests.append(['GET', self.path])
        if self.path == '/index/config.json':
            return self.respond(200, json.dumps({'dl': origin + '/crates/{crate}/{version}/download', 'api': origin}).encode())
        if self.path.startswith('/index/') and self.path.rsplit('/', 1)[-1] in records:
            return self.respond(200, records[self.path.rsplit('/', 1)[-1]])
        if self.path.startswith('/crates/') and self.path.split('/')[2] in archives:
            return self.respond(200, archives[self.path.split('/')[2]])
        self.respond(404, b'not found')
    def do_PUT(self):
        requests.append(['PUT', self.path])
        if self.path != '/api/v1/crates/new': return self.respond(403, b'only capture endpoint allowed')
        length = int(self.headers['Content-Length'])
        if not 0 < length < 1024*1024: return self.respond(413, b'oversized')
        body = self.rfile.read(length)
        (out / 'request.bin').write_bytes(body)
        self.respond(403, b'{"errors":[{"detail":"intentional local capture rejection; no publication"}]}')
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
origin = f'http://127.0.0.1:{server.server_port}'
(home / 'config.toml').write_text(f'''[source.crates-io]
replace-with = "dummy-registry"
[registries.dummy-registry]
index = "sparse+{origin}/index/"
credential-provider = "cargo:token"
[http]
proxy = "{origin}"
''')
env = {k:v for k,v in os.environ.items() if not k.startswith(('CARGO', 'RUST', 'QPERIAPT', 'DYLD', 'LD_', 'PYTHON')) and k.upper() not in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')}
env.update(CARGO_NET_RETRY='0', CARGO_HOME=str(home), RUSTC=str(tc/'bin/rustc'), RUSTDOC=str(tc/'bin/rustdoc'), DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'), CARGO_REGISTRIES_DUMMY_REGISTRY_TOKEN='LOCAL-NONCREDENTIAL', NO_PROXY='127.0.0.1', PATH=str(tc/'bin')+':/usr/bin:/bin:/opt/homebrew/bin')
thread = threading.Thread(target=server.serve_forever); thread.start()
command = [str(tc/'bin/cargo'), 'publish', '--registry', 'dummy-registry', '--allow-dirty']
try:
    result = subprocess.run(command, cwd=project, env=env, capture_output=True, timeout=120)
finally:
    server.shutdown(); thread.join(); server.server_close()
(out/'stdout.log').write_bytes(result.stdout); (out/'stderr.log').write_bytes(result.stderr)
(out/'requests.json').write_text(json.dumps(requests, indent=2)+'\n')
print(result.returncode, result.stderr.decode())
assert result.returncode != 0 and 'intentional local capture rejection' in result.stderr.decode()
assert not any(r[0]=='DENIED_CONNECT' for r in requests)
body = (out/'request.bin').read_bytes(); size = struct.unpack('<I', body[:4])[0]; metadata = body[4:4+size]
crate_size = struct.unpack('<I', body[4+size:8+size])[0]; crate = body[8+size:]; assert len(crate)==crate_size
(out/'registry-alias-fixture.metadata.json').write_bytes(metadata)
(out/'registry-alias-fixture.crate').write_bytes(crate)
with tarfile.open(fileobj=io.BytesIO(crate), mode='r:gz') as archive:
    for member, target in [('Cargo.toml','cargo.toml'),('README.md','readme.md')]:
        (out/f'registry-alias-fixture.{target}').write_bytes(archive.extractfile(f'registry-alias-fixture-0.0.0/{member}').read())
(out/'cargo-version.txt').write_bytes(subprocess.check_output([str(tc/'bin/cargo'), '-Vv'], env=env))
print(metadata.decode())
