import os.path as osp

from setuptools import setup, find_packages

cdir = osp.abspath(osp.dirname(__file__))
README = open(osp.join(cdir, 'readme.rst')).read()
CHANGELOG = open(osp.join(cdir, 'changelog.rst')).read()

version_fpath = osp.join(cdir, 'keg_auth', 'version.py')
version_globals = {}
with open(version_fpath) as fo:
    exec(fo.read(), version_globals)

setup(
    name='Keg-Auth',
    version=version_globals['VERSION'],
    description='Authentication plugin for Keg',
    long_description='\n\n'.join((README, CHANGELOG)),
    long_description_content_type='text/x-rst',
    author='Randy Syring',
    author_email='randy.syring@level12.io',
    url='https://github.com/level12/keg-auth',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
    ],
    packages=find_packages(exclude=[]),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'authlib',
        'bcrypt',
        'markdown-it-py',

        'Flask-Login>0.4.1',
        'Keg>=0.10.2',
        'KegElements>=0.8.0',
        'inflect',
        'passlib',
        'shortuuid',
        'webgrid>=0.4.13',
    ],
    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        'test': [
            'email_validator',
            'flake8',
            'flask-bootstrap',
            'flask-jwt-extended>=4.0.0',
            'flask-mail',
            'flask-webtest',
            'freezegun',
            'mock',
            'psycopg2-binary',
            'python-ldap==3.4.2',
            'pyquery',
            'pytest',
            'pytest-cov',
            'requests',
            'tox',
            'xlsxwriter',
        ],
        'i18n': [
            'morphi',
            'webgrid[i18n]'
        ],
        'jwt': [
            'flask-jwt-extended>=4.0.0',
        ],
        'ldap': [
            'python-ldap',
        ],
        'mail': [
            'Flask-Mail',
        ],
        'oauth': [
            'requests',
        ],
    }
)
