#!/usr/bin/env python3
"""Development packaging only; no Python component is included in the APK."""
import hashlib
import json
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
output = root / 'artifacts/android/ALiang-Proxy-Android-source.zip'
output.parent.mkdir(parents=True, exist_ok=True)
license_index = json.loads((root / 'android/app/src/main/assets/licenses/INDEX.json').read_text())
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    def add(path, destination=None):
        archive.write(path, destination or path.relative_to(root))
    for path in sorted((root / 'android').rglob('*')):
        rel = path.relative_to(root / 'android')
        if not path.is_file() or any(part in ('.gradle', 'build', '.cache') for part in rel.parts):
            continue
        if rel.parts[:2] == ('app', 'libs') or path.name == 'local.properties':
            continue
        if path.suffix in ('.p12', '.jks', '.keystore'):
            raise RuntimeError('unexpected signing key in source tree')
        add(path)
    for path in sorted((root / 'core/profile').glob('*.go')):
        add(path)
    for name in ('go.mod', 'go.sum', 'upstream.lock.json'):
        add(root / 'core' / name)
    for name in ('android-env.sh', 'build-android.sh', 'build-android-core.sh', 'test-android.sh', 'package-android-source.py'):
        add(root / 'scripts' / name)
    add(root / '.cache/sing-box-v1.14.4.tar.gz', 'upstream/sing-box-v1.14.4.tar.gz')
    for module in license_index + [{'module':'github.com/sagernet/gomobile','version':'v0.1.12'}]:
        version = module['version']
        if version == 'local':
            continue
        escaped = ''.join('!' + c.lower() if c.isupper() else c for c in module['module'])
        source = root / '.cache/go-mod/cache/download' / escaped / '@v' / (version + '.zip')
        if not source.is_file():
            raise RuntimeError('missing corresponding module source: ' + module['module'])
        add(source, 'module-sources/' + escaped.replace('/', '_') + '@' + version + '.zip')
print(output)
print('SHA256', hashlib.sha256(output.read_bytes()).hexdigest())
