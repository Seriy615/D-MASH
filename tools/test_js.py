#!/usr/bin/env python3
"""Run JS suites with exact-input hashes; keep raw synthetic stdout private."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--node', default=shutil.which('node'))
    parser.add_argument('--source-ref', help='Git SHA for an immutable archive without .git')
    parser.add_argument('--output-dir', type=pathlib.Path)
    parser.add_argument('--only', action='append', help='Exact test filename; repeat for a scoped run')
    args = parser.parse_args()
    root = args.repo.resolve()
    if not args.node:
        parser.error('Node v24.19.0 is required; pass --node PATH')
    version = subprocess.check_output([args.node, '--version'], text=True).strip()
    if version != 'v24.19.0':
        parser.error('Reference Node v24.19.0 required; pass --node PATH')
    source_ref = args.source_ref
    if source_ref is None:
        source_ref = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = args.output_dir or pathlib.Path.home() / '.cache/dmash-js-verification' / stamp
    out = out.resolve()
    if out == root or root in out.parents:
        parser.error('Raw stdout must be stored outside the repository')
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    out.chmod(0o700)
    base = root / 'D-MASH PWA/not_messenger'
    tests = sorted((base / 'tests').glob('*.test.js'))
    available = {p.name for p in tests}
    if args.only:
        if not set(args.only) <= available:
            parser.error('Unknown --only test filename')
        tests = [p for p in tests if p.name in args.only]
    if not tests:
        parser.error('No JS suites found')

    def hashes():
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(base.rglob('*')) if p.is_file()}

    before = hashes()
    rows = []
    started = time.monotonic()
    descriptor = os.open(out / 'raw-unit-stdout.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, 'w') as raw:
        for index, test in enumerate(tests, 1):
            begin = time.monotonic()
            try:
                result = subprocess.run([args.node, str(test)], cwd=root, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, timeout=180, check=False)
                code, output = result.returncode, result.stdout
            except subprocess.TimeoutExpired as exc:
                code = 124
                output = 'TIMEOUT after 180 seconds\n' + repr(exc.stdout)
            raw.write(f'\n===== {test.name} exit={code} =====\n{output}')
            raw.flush()
            rows.append({'name': test.name, 'exit_code': code,
                         'seconds': round(time.monotonic() - begin, 3)})
            print(f'{index}/{len(tests)} {"PASS" if code == 0 else "FAIL"} {test.name}', flush=True)
    after = hashes()
    report = {'source_commit': source_ref, 'scope': 'UNIT all JS suites' if not args.only else 'UNIT selected JS suites',
              'node': version, 'test_count': len(rows), 'passed': sum(r['exit_code'] == 0 for r in rows),
              'failed': sum(r['exit_code'] != 0 for r in rows),
              'duration_seconds': round(time.monotonic() - started, 3), 'inputs_unchanged': before == after,
              'source_files_sha256': before, 'tests': rows,
              'raw_stdout': {'storage': 'private output directory; not suitable for blind publication',
                             'sha256': hashlib.sha256((out / 'raw-unit-stdout.log').read_bytes()).hexdigest()}}
    (out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['test_count', 'passed', 'failed', 'inputs_unchanged']}))
    return int(report['failed'] != 0 or not report['inputs_unchanged'])


if __name__ == '__main__':
    sys.exit(main())
