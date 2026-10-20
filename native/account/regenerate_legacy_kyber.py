#!/usr/bin/env python3
"""Reproduce the existing WASM translation with the pinned WABT tool (not a new KEM)."""
import argparse
import hashlib
from pathlib import Path
import subprocess

EXPECTED = 'e9b316e56f5d1eef1f44f28bca99bec16ec9cff69af4b17d318143512255b009'
parser = argparse.ArgumentParser()
parser.add_argument('--wasm2c', default='wasm2c')
args = parser.parse_args()
here = Path(__file__).resolve().parent
wasm = here.parent.parent / 'D-MASH PWA/not_messenger/js/vendor/kyber768.wasm'
if hashlib.sha256(wasm.read_bytes()).hexdigest() != EXPECTED:
    raise SystemExit('Existing Account WASM differs; explicit compatibility review required')
version = subprocess.check_output([args.wasm2c, '--version'], text=True).strip()
if version != '1.0.34':
    raise SystemExit(f'Expected WABT 1.0.34, found {version!r}')
subprocess.run([args.wasm2c, str(wasm), '-n', 'dmash_legacy_kyber',
                '-o', str(here / 'vendor/kyber.c')], check=True)
print('Regenerated unchanged existing Account WASM using WABT 1.0.34')
