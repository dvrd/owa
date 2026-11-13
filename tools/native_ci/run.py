#!/usr/bin/env python3
"""Run account-free OWA native gates with immutable SDK/dependency provenance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time

import assets

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MAX_LOG = 16 << 20
COMPAT_PRIOR = "fa2734f60b60cc9770809bb1be873cea60fe3c12"


class GateError(Exception): pass


def host_key():
    system, machine = platform.system(), platform.machine()
    if system == 'Linux' and machine == 'x86_64':
        release = platform.freedesktop_os_release()
        if (release.get('ID'), release.get('VERSION_ID')) != ('ubuntu', '24.04'):
            raise GateError('UBUNTU_24_04_REQUIRED')
        return 'linux-amd64'
    if system == 'Darwin' and machine == 'arm64': return 'macos-arm64'
    raise GateError('NATIVE_HOST_UNSUPPORTED')


def tracked(root):
    paths = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
    result = {}
    for name in filter(None, paths):
        path = root/assets.relative(name)
        if path.is_symlink() or not path.is_file(): raise GateError('CHECKOUT_FILE_INVALID')
        result[name] = assets.digest(path)
    return result


def snapshot(root):
    result = {}
    for path in root.rglob('*'):
        if path.is_symlink(): raise GateError('INPUT_SYMLINK')
        if path.is_file(): result[path.relative_to(root).as_posix()] = assets.digest(path)
    return result


def terminate(child):
    try: os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    try: child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait(timeout=5)


def execute(argv, label, evidence, env, rows, timeout=240):
    log = evidence/(label+'.log'); exceeded = threading.Event()
    print(json.dumps({'phase': 'COMMAND_STARTED', 'name': label}), flush=True)
    child = subprocess.Popen(list(map(str, argv)), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env, start_new_session=True)
    def drain():
        size = 0
        with child.stdout, log.open('wb') as output:
            while block := child.stdout.read(65536):
                accepted = min(len(block), MAX_LOG-size)
                output.write(block[:accepted]); size += accepted
                if accepted != len(block): exceeded.set(); return
    reader = threading.Thread(target=drain, daemon=True); reader.start()
    started = time.monotonic(); failure = None
    while child.poll() is None:
        if exceeded.is_set() or time.monotonic()-started >= timeout:
            failure = 'OUTPUT_LIMIT' if exceeded.is_set() else 'TIMEOUT'; terminate(child); break
        time.sleep(.05)
    reader.join(timeout=5)
    if reader.is_alive():
        terminate(child)
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        reader.join(timeout=5); failure = 'OUTPUT_PIPE_NOT_RETIRED'
    if exceeded.is_set(): failure = failure or 'OUTPUT_LIMIT'
    row = {'name': label, 'command': list(map(str, argv)), 'exit_code': child.returncode,
           'elapsed_seconds': time.monotonic()-started, 'failure': failure,
           'log': log.name, 'log_sha256': assets.digest(log)}
    rows.append(row)
    print(json.dumps({'phase': 'COMMAND_FINISHED', 'name': label,
                      'exit_code': child.returncode, 'failure': failure}), flush=True)
    if failure or exceeded.is_set() or child.returncode: raise GateError('COMMAND_FAILED: '+label)


def environment(sdk):
    value = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL') if key in os.environ}
    value.update(ODIN_ROOT=str(sdk), PYTHONDONTWRITEBYTECODE='1', AWS_EC2_METADATA_DISABLED='true')
    if platform.system() == 'Darwin': value['DYLD_LIBRARY_PATH'] = str(sdk/'lib')
    return value


def file_identity(path):
    path = path.resolve(strict=True)
    if not path.is_file(): raise GateError('TOOLCHAIN_FILE_REQUIRED')
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': assets.digest(path)}


def linker_runtime(platform_key, evidence, env, rows):
    selected = os.environ.get('OWA_NATIVE_CLANG', '')
    if not selected or not Path(selected).is_absolute(): raise GateError('EXPLICIT_CLANG_REQUIRED')
    driver = Path(selected).resolve(strict=True)
    if not os.access(driver, os.X_OK): raise GateError('CLANG_EXECUTABLE_REQUIRED')
    ambient = shutil.which('clang', path=env.get('PATH'))
    metadata = {'driver': file_identity(driver), 'ambient_driver': None, 'sanitizer_runtimes': {}}
    if ambient:
        metadata['ambient_driver'] = file_identity(Path(ambient))
        execute([ambient, '--version'], 'ambient-clang-version', evidence, env, rows)
        metadata['ambient_version'] = (evidence/'ambient-clang-version.log').read_text().strip()
    env['PATH'] = str(driver.parent)+os.pathsep+env.get('PATH', '')
    effective = shutil.which('clang', path=env['PATH'])
    if effective is None or Path(effective).resolve() != driver:
        raise GateError('CLANG_PATH_SELECTION_MISMATCH')
    execute([driver, '--version'], 'selected-clang-version', evidence, env, rows)
    version = (evidence/'selected-clang-version.log').read_text().strip()
    metadata['version'] = version
    match = re.search(r'\bclang version ([0-9]+)\.', version)
    expected = 22 if platform_key == 'macos-arm64' else 18
    if match is None or int(match[1]) != expected: raise GateError('CLANG_MAJOR_MISMATCH')
    execute([driver, '-print-resource-dir'], 'selected-clang-resource', evidence, env, rows)
    resource = Path((evidence/'selected-clang-resource.log').read_text().strip())
    if not resource.is_absolute() or not resource.is_dir(): raise GateError('CLANG_RESOURCE_INVALID')
    metadata['resource_directory'] = str(resource.resolve())
    for sanitizer in ('address', 'thread'):
        short = 'asan' if sanitizer == 'address' else 'tsan'
        relative = ('lib/darwin/libclang_rt.'+short+'_osx_dynamic.dylib'
                    if platform_key == 'macos-arm64' else 'lib/linux/libclang_rt.'+short+'-x86_64.a')
        metadata['sanitizer_runtimes'][sanitizer] = file_identity(resource/relative)
    if platform_key == 'macos-arm64':
        execute(['/usr/bin/nm', '-gU', metadata['sanitizer_runtimes']['address']['path']],
                'asan-runtime-abi', evidence, env, rows)
        if '___asan_version_mismatch_check_v8' not in (evidence/'asan-runtime-abi.log').read_text():
            raise GateError('ASAN_RUNTIME_ABI_MISMATCH')
    return metadata


def compatibility_argv(copied, repository, revision, downloads, clang, sanitizer, report_path):
    if not re.fullmatch(r'[0-9a-f]{40}', revision): raise GateError('EXACT_COMPATIBILITY_REVISION_REQUIRED')
    # The child exclusively creates this unpredictable direct /tmp path. It must
    # not be inside the guarded SDK, checkout or evidence trees.
    work = Path('/tmp')/('owa-format-compat-'+sanitizer+'-'+secrets.token_hex(12))
    return [sys.executable, copied/'tests/encrypted_recovery/compatibility.py',
            '--repository', repository, '--current-revision', revision,
            '--assets-dir', downloads, '--clang', clang, '--sanitize', sanitizer,
            '--work', work, '--report', report_path]


def compatibility_result(path, revision):
    result = json.loads(path.read_bytes())
    if result.get('passed') is not True or result.get('current_commit') != revision or \
            result.get('prior_commit') != COMPAT_PRIOR:
        raise GateError('COMPATIBILITY_IDENTITY_OR_RESULT_MISMATCH')
    return {'passed': True, 'prior_commit': result['prior_commit'],
            'current_commit': revision, 'report_sha256': assets.digest(path)}


def coupled_recovery_result(path, copied):
    result = json.loads(path.read_bytes())
    socket = result.get('socket_recovery', {})
    if result.get('passed') is not True or result.get('source_unchanged') is not True or \
            result.get('compiler_unchanged') is not True or socket.get('transport') != 'native-tcp' or \
            socket.get('coupled_native_tcp_verified') is not True:
        raise GateError('COUPLED_NATIVE_TCP_RECOVERY_REQUIRED')
    # Reuse the exact producer validator from the guarded physical source copy.
    source = copied/'tests/encrypted_recovery/native_tcp.py'
    spec = importlib.util.spec_from_file_location('coupled_recovery_validator', source)
    validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)
    stages = ('socket-before-send', 'socket-after-commit-before-write',
              'socket-after-wire-before-return', 'socket-after-send-before-ack',
              'socket-after-positive-ack', 'socket-after-ack-journal')
    try: summary = validator.validate_peers(result.get('native_tcp_peers', []), stages)
    except (validator.TCPError, KeyError, TypeError, ValueError) as error:
        raise GateError('COUPLED_NATIVE_TCP_PEERS_INVALID') from error
    if socket.get('native_tcp_summary') != summary:
        raise GateError('COUPLED_NATIVE_TCP_SUMMARY_MISMATCH')
    return {'passed': True, 'report_sha256': assets.digest(path), **summary}


def run(args, report):
    pin = json.loads((HERE/'pin.json').read_bytes())
    if pin.get('schema') != 1 or pin.get('repository') != assets.REPOSITORY:
        raise GateError('PIN_INVALID')
    key = host_key(); report['platform'] = key
    if not args.allow_local and os.environ.get('GITHUB_ACTIONS') != 'true':
        raise GateError('GITHUB_RUNNER_REQUIRED')
    status = subprocess.check_output(['git', '-C', str(REPO), 'status', '--porcelain'], text=True)
    if status and not args.allow_dirty: raise GateError('CLEAN_CHECKOUT_REQUIRED')
    report.update(checkout_clean=not status, checkout_commit=subprocess.check_output(
        ['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
        github_run_id=os.environ.get('GITHUB_RUN_ID'), pin_sha256=assets.digest(HERE/'pin.json'))
    before_checkout = tracked(REPO)
    report['checkout_source_before'] = before_checkout
    downloads = args.work/'objects'; downloads.mkdir()
    sdk = args.work/'sdk'
    expected_sdk = assets.install(pin, pin['platforms'][key], downloads, sdk, args.assets_dir)
    shared = sdk/'shared'
    expected_dependencies = assets.install(pin, pin['dependencies'], downloads, shared, args.assets_dir)
    copied = shared/'whatsapp'; copied.mkdir()
    for name, expected in before_checkout.items():
        source = REPO/name; target = copied/name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if assets.digest(target) != expected: raise GateError('CHECKOUT_CHANGED_DURING_COPY')
    compiler = sdk/'odin'; env = environment(sdk); rows = report['commands']
    report.update(compiler_sha256=assets.digest(compiler), core_source_revision=pin['core_source_revision'],
                  compiler_source_revision=pin['compiler_source_revision'],
                  dependency_manifest_sha256=pin['dependencies']['manifest']['sha256'])
    before = snapshot(sdk); report['input_before'] = before
    source_before = {str(path.relative_to(HERE)): assets.digest(path)
                     for path in HERE.rglob('*') if path.is_file() and '__pycache__' not in path.parts}
    report['runner_source_before'] = source_before
    try:
        report['linker_runtime'] = linker_runtime(key, args.evidence, env, rows)
        execute([compiler, 'version'], 'compiler-version', args.evidence, env, rows)
        report['compiler_version'] = (args.evidence/'compiler-version.log').read_text().strip()
        if pin['compiler_version'] not in report['compiler_version']:
            raise GateError('COMPILER_VERSION_MISMATCH')
        flags = ['-collection:shared='+str(shared), '-vet', '-warnings-as-errors', '-thread-count:1']
        probe = args.evidence/'empty'; probe.mkdir()
        (probe/'main.odin').write_text('package main\nimport "core:fmt"\nmain :: proc(){fmt.println("NATIVE_SANITIZER_EXECUTED")}\n')
        for sanitizer in args.sanitizers:
            mode = ['-sanitize:'+sanitizer]
            binary = args.evidence/('empty-'+sanitizer)
            execute([compiler, 'build', probe, *flags, *mode, '-out:'+str(binary)],
                    'empty-build-'+sanitizer, args.evidence, env, rows)
            probe_env = dict(env)
            if key == 'macos-arm64': probe_env['DYLD_PRINT_LIBRARIES'] = '1'
            execute([binary], 'empty-run-'+sanitizer, args.evidence, probe_env, rows)
            if key == 'macos-arm64':
                runtime = report['linker_runtime']['sanitizer_runtimes'][sanitizer]['path']
                if runtime not in (args.evidence/('empty-run-'+sanitizer+'.log')).read_text():
                    raise GateError('LOADED_SANITIZER_RUNTIME_MISMATCH')
            for name, package in [('unit', copied), ('qualification-tools', copied/'tools/live_qualification')]:
                execute([compiler, 'test', package, *flags, *mode,
                    '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true',
                    '-out:'+str(args.evidence/(name+'-'+sanitizer))],
                    name+'-'+sanitizer, args.evidence, env, rows, 600)
            for name in ('loopback_noise', 'recovery_campaign', 'encrypted_recovery'):
                report_path = args.evidence/(name+'-'+sanitizer+'.json')
                argv = [sys.executable, copied/'tests'/name/'run.py', '--odin', compiler,
                    '--shared-root', shared, '--sanitize', sanitizer, '--report', report_path]
                if name == 'recovery_campaign': argv += ['--scorecard', args.evidence/('chaos-'+sanitizer+'.tsv')]
                if name == 'encrypted_recovery': argv += ['--socket-transport', 'native-tcp']
                execute(argv, name+'-'+sanitizer, args.evidence, env, rows, 900)
                if name == 'encrypted_recovery':
                    report.setdefault('coupled_native_tcp_recovery', {})[sanitizer] = \
                        coupled_recovery_result(report_path, copied)
            compatibility_report = args.evidence/('compatibility-'+sanitizer+'.json')
            argv = compatibility_argv(copied, REPO, report['checkout_commit'], downloads,
                report['linker_runtime']['driver']['path'], sanitizer, compatibility_report)
            execute(argv, 'compatibility-'+sanitizer, args.evidence, env, rows, 900)
            report.setdefault('compatibility', {})[sanitizer] = compatibility_result(
                compatibility_report, report['checkout_commit'])
            consumer = args.evidence/('consumer-'+sanitizer)
            execute([compiler, 'build', HERE/'consumer', *flags, *mode, '-out:'+str(consumer)],
                    'consumer-build-'+sanitizer, args.evidence, env, rows)
            execute([consumer], 'consumer-run-'+sanitizer, args.evidence, env, rows)
        report['passed'] = True
    finally:
        report['input_after'] = snapshot(sdk)
        report['checkout_source_after'] = tracked(REPO)
        report['checkout_unchanged'] = before_checkout == report['checkout_source_after']
        report['source_unchanged'] = before == report['input_after']
        report['runner_source_after'] = {str(path.relative_to(HERE)): assets.digest(path)
            for path in HERE.rglob('*') if path.is_file() and '__pycache__' not in path.parts}
        report['runner_unchanged'] = source_before == report['runner_source_after']
        identities = report.get('linker_runtime', {})
        selected = [identities['driver']] if identities.get('driver') else []
        selected += list(identities.get('sanitizer_runtimes', {}).values())
        report['linker_runtime_unchanged'] = all(file_identity(Path(item['path'])) == item for item in selected)
        report['passed'] = report['passed'] and report['source_unchanged'] and \
            report['checkout_unchanged'] and report['runner_unchanged'] and report['linker_runtime_unchanged']
        assets.verify_tree(sdk, expected_sdk, extra_root='shared')
        assets.verify_tree(shared, expected_dependencies, extra_root='whatsapp')
    if not report['passed']: raise GateError('INPUTS_CHANGED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--assets-dir', type=Path)
    parser.add_argument('--allow-local', action='store_true')
    parser.add_argument('--allow-dirty', action='store_true')
    parser.add_argument('--sanitizers', nargs='+', choices=('address', 'thread'), default=['address', 'thread'])
    args = parser.parse_args()
    args.work = args.work.resolve(); args.evidence = args.evidence.resolve()
    if args.work.is_relative_to(REPO) or args.evidence.is_relative_to(args.work) or args.evidence.is_relative_to(REPO):
        parser.error('work and evidence must be separate external directories')
    args.work.mkdir(mode=0o700); args.evidence.mkdir(mode=0o700)
    report = {'schema': 1, 'passed': False, 'commands': [],
        'scope': 'OWA native units/tools + synthetic Noise/recovery + executable API consumer; no live accounts or full Webtools/Mesa certification'}
    try: run(args, report)
    except (GateError, assets.AssetError, OSError, ValueError, KeyError, TypeError) as error:
        report['passed'] = False
        report['failure'] = type(error).__name__+': '+str(error)[:300]
    finally:
        (args.evidence/'qualification.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
        files = {path.name: assets.digest(path) for path in args.evidence.iterdir() if path.is_file()}
        (args.evidence/'checksums.json').write_text(json.dumps(files, sort_keys=True, indent=2)+'\n')
    print(json.dumps({'passed': report['passed'], 'failure': report.get('failure'), 'platform': report.get('platform')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__': sys.exit(main())
