import os.path as osp

from setuptools import setup, find_packages

cdir = osp.abspath(osp.dirname(__file__))
README = open(osp.join(cdir, 'readme.rst')).read()
CHANGELOG = open(osp.join(cdir, 'changelog.rst')).read()

version_fpath = osp.join(cdir, 'kegauth', 'version.py')
version_globals = {}
with open(version_fpath) as fo:
    exec(fo.read(), version_globals)

setup(
    name='Keg Auth',
    version=version_globals['VERSION'],
    description='Authentication plugin for Keg',
    long_description='\n\n'.join((README, CHANGELOG)),
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
        'bcrypt',
        'commonmark',
        'Flask-Mail',
        'Flask-Login',
        'KegElements',
        'passlib',
        'shortuuid',
    ],
    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        'dev': [
            'flask-bootstrap'
        ],
        'test': [
            'flake8',
            'flask-webtest',
            'freezegun',
            'mock',
            'pyquery',
            'pytest',
            'pytest-cov',
            'tox',
        ],
    }
)
