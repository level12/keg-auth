from os import environ
from pathlib import Path

import nox


package_path = Path(__file__).parent.resolve()
nox.options.default_venv_backend = 'uv'
nox.options.sessions = [
    'pytest',
    'pytest_stable',
    'pytest_psycopg2',
    'i18n',
    'build',
    'docs',
    'prek',
    'audit',
]


@nox.session(python=['3.12', '3.13', '3.14'])
def pytest(session: nox.Session):
    uv_sync(session, 'pytest')
    pytest_run(session)


@nox.session(python=['3.12', '3.13', '3.14'])
def pytest_stable(session: nox.Session):
    session.install('-r', 'stable-requirements.txt', '.')
    pytest_run(session)


@nox.session(python='3.14')
def pytest_psycopg2(session: nox.Session):
    uv_sync(session, 'pytest', 'psycopg2')
    session.run(
        'uv',
        'pip',
        'uninstall',
        '--python',
        session.virtualenv.location,
        'psycopg',
        'psycopg-binary',
    )
    pytest_run(session, POSTGRES_DRIVER='+psycopg2')


@nox.session(python='3.14')
def i18n(session: nox.Session):
    uv_sync(session, 'pytest', 'i18n', project=True)
    pytest_run(session)
    session.run('python', '-m', 'keg_auth_ta.app', '--profile=TestProfile', 'verify-translations')


@nox.session
def prek(session: nox.Session):
    uv_sync(session)
    session.run('prek', 'run', '--all-files')


@nox.session
def audit(session: nox.Session):
    uv_sync(session, 'audit', 'pytest', project=True)
    session.run('pip-audit', '--desc', '--skip-editable', *pip_audit_ignore_args())


@nox.session
def docs(session: nox.Session):
    uv_sync(session, 'docs', project=True)
    session.run(
        'sphinx-build', '-W', '--keep-going', '-b', 'html', 'docs/source', 'docs/build/html'
    )


@nox.session
def build(session: nox.Session):
    uv_sync(session, 'build', 'pytest')
    output_dir = Path(
        environ.get('KEG_AUTH_DIST_DIR', Path(session.create_tmp()) / 'dist')
    ).resolve()
    # The default build creates the wheel from the sdist, exercising both distributions.
    session.run('python', '-m', 'build', '--outdir', str(output_dir))
    session.run('twine', 'check', *map(str, output_dir.glob('*')))
    session.run('python', 'tasks/check-dist.py', str(output_dir))
    (wheel_path,) = output_dir.glob('*.whl')
    session.run(
        'uv',
        'pip',
        'install',
        '--python',
        session.virtualenv.location,
        '--reinstall',
        '--no-deps',
        str(wheel_path),
    )
    session.chdir(session.create_tmp())
    session.run(
        'python',
        '-I',
        '-c',
        'from keg_auth_ta.app import KegAuthTestApp; import keg_auth; print(keg_auth.__file__)',
    )


def pytest_run(session: nox.Session, **env):
    session.run(
        'pytest',
        '-ra',
        '--tb=short',
        '--strict-markers',
        '--cov',
        '--cov-report=xml',
        '--no-cov-on-fail',
        f'--junit-xml={package_path}/ci/test-reports/{session.name}.xml',
        str(package_path / 'tests'),
        *session.posargs,
        env=env,
    )


def uv_sync(session: nox.Session, *groups, project=False):
    if not groups:
        groups = (session.name,)
    project_args = () if project or session.name.startswith('pytest') else ('--no-install-project',)
    group_args = [arg for group in groups for arg in ('--group', group)]
    session.run(
        'uv',
        'sync',
        '--active',
        '--frozen',
        '--exact',
        '--no-default-groups',
        *project_args,
        *group_args,
    )


def pip_audit_ignore_args():
    path = package_path / 'pip-audit-ignore.txt'
    if not path.exists():
        return []
    ids = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith('#')
    ]
    return [arg for vuln_id in ids for arg in ('--ignore-vuln', vuln_id)]
