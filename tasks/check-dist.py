"""Verify that both distributions preserve every package source file and resource."""

from pathlib import Path
import sys
import tarfile
import zipfile


root = Path(__file__).resolve().parents[1]
dist = Path(sys.argv[1])
# Include new files during migration, but exclude runtime caches and build products.
expected = {
    path.relative_to(root / 'src').as_posix()
    for package in ('keg_auth', 'keg_auth_ta')
    for path in (root / 'src' / package).rglob('*')
    if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'
}
(wheel,) = dist.glob('*.whl')
(sdist,) = dist.glob('*.tar.gz')
with zipfile.ZipFile(wheel) as archive:
    missing = expected - set(archive.namelist())
    if missing:
        raise SystemExit(f'Wheel missing package files: {sorted(missing)}')
with tarfile.open(sdist) as archive:
    names = {'/'.join(name.split('/')[1:]) for name in archive.getnames()}
    missing = {f'src/{name}' for name in expected} - names
    if missing:
        raise SystemExit(f'Sdist missing package files: {sorted(missing)}')
print(f'Verified {len(expected)} package files in wheel and sdist')
