#!/usr/bin/env python3
"""Run public tests and stage private tests without widening library APIs."""
import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd, environment):
    child = subprocess.Popen(command, cwd=cwd, env=environment, start_new_session=True)
    try:
        code = child.wait(timeout=300)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        raise
    if code:
        raise subprocess.CalledProcessError(code, command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', default=os.environ.get('ODIN', 'odin'))
    parser.add_argument('--package', default='all')
    parser.add_argument('--internal-only', action='store_true')
    parser.add_argument('flags', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    flags = args.flags[1:] if args.flags[:1] == ['--'] else args.flags
    suites = []
    private_directories = []
    for directory in sorted({p.parent for p in ROOT.rglob('*_test.odin')
                             if '.git' not in p.parts}):
        relative = directory.relative_to(ROOT)
        private = relative.parts[-2:] == ('tests', 'internal')
        if private:
            private_directories.append(relative)
        package = relative.parent.parent if private else relative.parent
        if args.package != 'all' and str(package) != args.package:
            continue
        if not args.internal_only or private:
            suites.append((relative, private))
    if not suites:
        parser.error('no matching test suites')
    with tempfile.TemporaryDirectory(prefix='odin-library-tests-') as temporary:
        shared = Path(temporary) / 'shared'
        shared.mkdir()
        staged = shared / ROOT.name
        for source_root in ROOT.parent.iterdir():
            if not source_root.is_dir() or source_root.name.startswith('.'):
                continue
            if (ROOT / '.git').exists() and not (source_root / '.git').exists():
                continue
            if source_root.name == 'metalized' and source_root != ROOT:
                continue
            if (source_root / '.git').exists():
                names = subprocess.check_output([
                    'git', '-C', str(source_root), 'ls-files', '--cached', '--others',
                    '--exclude-standard', '-z']).decode().split('\0')
            else:
                names = [str(p.relative_to(source_root)) for p in source_root.rglob('*')
                         if p.is_file() and not any(part.startswith('.') or part == '__pycache__'
                             for part in p.relative_to(source_root).parts)]
            for name in filter(None, names):
                source = source_root / name
                if not source.is_file():
                    continue
                destination = shared / source_root.name / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        compiler = str(Path(shutil.which(args.odin) or args.odin).resolve())
        sdk = Path(subprocess.check_output([compiler, 'root'], text=True).strip())
        for name in ('base', 'core', 'vendor'):
            (Path(temporary) / name).symlink_to(sdk / name, target_is_directory=True)
        wrapper = Path(temporary) / 'odin'
        wrapper.write_text('#!/usr/bin/env python3\nimport os, sys\n'
                           'compiler = ' + repr(compiler) + '\n'
                           'if sys.argv[1:] == ["root"]:\n'
                           '    print(' + repr(temporary) + '); sys.exit(0)\n'
                           'args = [arg for arg in sys.argv[1:] if not arg.startswith("-collection:shared=")]\n'
                           'if args[:1] != ["version"]: args.append(' +
                           repr('-collection:shared=' + str(shared)) + ')\n'
                           'os.execv(compiler, [compiler, *args])\n')
        wrapper.chmod(0o755)
        environment = dict(os.environ, ODIN=str(wrapper))
        flags = ['-collection:shared=' + str(shared),
                 *(f for f in flags if not f.startswith('-collection:shared='))]
        for relative in private_directories:
            target = (staged / relative).parent.parent
            for source in (staged / relative).glob('*.odin'):
                shutil.copy2(source, target / source.name)
        for relative, private in suites:
            target = staged / relative
            if private:
                target = target.parent.parent
            output = [] if any(f.startswith('-out:') for f in flags) else [
                '-out:' + str(Path(temporary) / 'tests')]
            print(f'Testing {relative}', flush=True)
            run([compiler, 'test', str(target), *output, *flags], shared, environment)


if __name__ == '__main__':
    main()
