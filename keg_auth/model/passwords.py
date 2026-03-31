import base64
import binascii
import hashlib
import hmac
import os
import weakref

import bcrypt
from sqlalchemy import types
from sqlalchemy.dialects import oracle, postgresql, sqlite
from sqlalchemy.ext.mutable import Mutable

from sqlalchemy_utils.types.scalar_coercible import ScalarCoercible


PBKDF2_SHA256_PREFIX = '$pbkdf2-sha256$'
DEFAULT_BCRYPT_ROUNDS = 12
DEFAULT_PBKDF2_SHA256_ROUNDS = 29000
SUPPORTED_SCHEMES = ('bcrypt', 'pbkdf2_sha256', 'plaintext')
_AB64_ENCODE_TRANS = str.maketrans('+/', './')
_AB64_DECODE_TRANS = str.maketrans('./', '+/')


class UnknownHashError(ValueError):
    pass


def _secret_to_bytes(secret):
    if isinstance(secret, bytes):
        return secret
    if isinstance(secret, str):
        return secret.encode('utf8')
    raise TypeError(f'Unsupported secret type: {type(secret)!r}')


def _secret_to_text(secret):
    if isinstance(secret, str):
        return secret
    if isinstance(secret, bytes):
        return secret.decode('utf8')
    raise TypeError(f'Unsupported secret type: {type(secret)!r}')


def _hash_to_text(password_hash):
    if isinstance(password_hash, bytes):
        return password_hash.decode('utf8')
    if isinstance(password_hash, str):
        return password_hash
    raise TypeError(f'Unsupported hash type: {type(password_hash)!r}')


def _ab64_encode(raw):
    return base64.b64encode(raw).decode('ascii').rstrip('=').translate(_AB64_ENCODE_TRANS)


def _ab64_decode(encoded):
    translated = encoded.translate(_AB64_DECODE_TRANS)
    padding = '=' * (-len(translated) % 4)
    return base64.b64decode(translated + padding)


class PasswordHash(Mutable):
    @classmethod
    def coerce(cls, key, value):
        if isinstance(value, PasswordHash):
            return value

        if isinstance(value, (str, bytes)):
            return cls(value, secret=True)

        return super().coerce(key, value)

    def __init__(self, value, context=None, secret=False):
        self.hash = value if not secret else None
        self.secret = value if secret else None

        if isinstance(self.hash, str):
            self.hash = self.hash.encode('utf8')

        self.context = weakref.proxy(context) if context is not None else None

    def __eq__(self, value):
        if self.hash is None or value is None:
            return self.hash is value

        if isinstance(value, PasswordHash):
            # This is not the normal authentication path, but keep the fallback comparison
            # constant-time so we don't introduce an avoidable timing side channel.
            return hmac.compare_digest(value.hash, self.hash)

        if self.context is None:
            return value == self

        if isinstance(value, (str, bytes)):
            valid, new = self.context.verify_and_update(value, self.hash)
            if valid and new:
                self.hash = new.encode('utf8') if isinstance(new, str) else new
                self.changed()
            return valid

        return False

    def __ne__(self, value):
        return not (self == value)


class PasswordContext:
    def __init__(self, schemes, deprecated='auto', **kwargs):
        if not schemes:
            raise ValueError('At least one password scheme is required')

        unknown = set(schemes) - set(SUPPORTED_SCHEMES)
        if unknown:
            raise ValueError(f'Unsupported password schemes: {sorted(unknown)!r}')

        self._schemes = tuple(schemes)
        self._preferred_scheme = self._schemes[0]
        self._deprecated = self._build_deprecated_set(deprecated)
        self.bcrypt_rounds = kwargs.get('bcrypt__rounds', DEFAULT_BCRYPT_ROUNDS)
        self.pbkdf2_sha256_rounds = kwargs.get(
            'pbkdf2_sha256__rounds',
            DEFAULT_PBKDF2_SHA256_ROUNDS,
        )

    def _build_deprecated_set(self, deprecated):
        if deprecated == 'auto':
            return set(self._schemes[1:])
        if deprecated is None:
            return set()
        if isinstance(deprecated, str):
            return {deprecated}
        return set(deprecated)

    def schemes(self):
        return self._schemes

    def hash(self, secret):
        return self._hash_with_scheme(secret, self._select_hash_scheme(secret))

    def verify(self, secret, password_hash):
        valid, _ = self.verify_and_update(secret, password_hash)
        return valid

    def verify_and_update(self, secret, password_hash):
        password_hash = _hash_to_text(password_hash)
        scheme = self._identify_scheme(password_hash)
        valid, legacy_truncation = self._verify(secret, password_hash, scheme)
        if not valid:
            return False, None

        target_scheme = self._select_hash_scheme(secret)
        # Mirror passlib/sqlalchemy-utils semantics: successful verification may yield a
        # replacement hash when the stored value uses a deprecated scheme or outdated
        # parameters. Callers using PasswordHash.__eq__ will transparently store that new
        # hash back onto the wrapped object.
        if self._needs_update(password_hash, scheme, target_scheme, legacy_truncation):
            return True, self._hash_with_scheme(secret, target_scheme)

        return True, None

    def _select_hash_scheme(self, secret):
        secret_bytes = _secret_to_bytes(secret)
        for scheme in self._schemes:
            # bcrypt only covers the first 72 bytes of a secret. For new hashes, do not create
            # a bcrypt hash for longer input; prefer the next configured scheme that can cover
            # the entire secret.
            if scheme != 'bcrypt' or len(secret_bytes) <= 72:
                return scheme
        raise ValueError('No configured password scheme can hash the supplied secret')

    def _identify_scheme(self, password_hash):
        # Identify the stored hash format from its serialized prefix. We only support the
        # formats we generate or have historically generated through passlib.
        if password_hash.startswith(('$2a$', '$2b$', '$2y$')):
            return 'bcrypt'
        if password_hash.startswith(PBKDF2_SHA256_PREFIX):
            return 'pbkdf2_sha256'
        if 'plaintext' in self._schemes:
            return 'plaintext'
        raise UnknownHashError('Unrecognized password hash format')

    def _verify(self, secret, password_hash, scheme):
        if scheme == 'bcrypt':
            secret_bytes = _secret_to_bytes(secret)
            if len(secret_bytes) > 72:
                # Legacy bcrypt inputs only authenticate against the first 72 bytes. Preserve
                # that behavior conservatively for compatibility with hashes that may have been
                # created when longer input was silently truncated. We intentionally do not
                # rehash on success because we cannot prove the bytes after 72 were ever part of
                # the original effective secret.
                return (
                    bcrypt.checkpw(secret_bytes[:72], password_hash.encode('ascii')),
                    True,
                )

            try:
                return bcrypt.checkpw(secret_bytes, password_hash.encode('ascii')), False
            except ValueError:
                return False, False

        if scheme == 'pbkdf2_sha256':
            return self._verify_pbkdf2_sha256(secret, password_hash), False

        if scheme == 'plaintext':
            return (
                hmac.compare_digest(_secret_to_bytes(secret), password_hash.encode('utf8')),
                False,
            )

        raise UnknownHashError(f'Unsupported password scheme: {scheme}')

    def _needs_update(self, password_hash, current_scheme, target_scheme, legacy_truncation):
        if legacy_truncation:
            # Do not auto-upgrade legacy bcrypt hashes that only matched after truncating the
            # presented secret. Upgrading would incorrectly assume the bytes after the first 72
            # were part of the original intended secret.
            return False

        if current_scheme != target_scheme or current_scheme in self._deprecated:
            return True

        if current_scheme == 'bcrypt':
            return self._bcrypt_rounds(password_hash) != self.bcrypt_rounds

        if current_scheme == 'pbkdf2_sha256':
            return self._pbkdf2_rounds(password_hash) != self.pbkdf2_sha256_rounds

        return False

    def _hash_with_scheme(self, secret, scheme):
        if scheme == 'bcrypt':
            return bcrypt.hashpw(
                _secret_to_bytes(secret),
                bcrypt.gensalt(rounds=self.bcrypt_rounds),
            ).decode('ascii')

        if scheme == 'pbkdf2_sha256':
            # Keep the on-disk format compatible with passlib's pbkdf2_sha256 encoding so
            # existing hashes remain verifiable and successful auth can migrate them forward.
            salt = os.urandom(16)
            checksum = hashlib.pbkdf2_hmac(
                'sha256',
                _secret_to_bytes(secret),
                salt,
                self.pbkdf2_sha256_rounds,
            )
            return (
                f'{PBKDF2_SHA256_PREFIX}{self.pbkdf2_sha256_rounds}$'
                f'{_ab64_encode(salt)}${_ab64_encode(checksum)}'
            )

        if scheme == 'plaintext':
            return _secret_to_text(secret)

        raise UnknownHashError(f'Unsupported password scheme: {scheme}')

    def _verify_pbkdf2_sha256(self, secret, password_hash):
        rounds = self._pbkdf2_rounds(password_hash)
        try:
            _, _, rounds_str, salt_encoded, checksum_encoded = password_hash.split('$')
            if rounds_str != str(rounds):
                return False
            salt = _ab64_decode(salt_encoded)
            checksum = _ab64_decode(checksum_encoded)
        except (ValueError, binascii.Error) as exc:
            raise UnknownHashError('Invalid pbkdf2_sha256 hash format') from exc

        calculated = hashlib.pbkdf2_hmac(
            'sha256',
            _secret_to_bytes(secret),
            salt,
            rounds,
            len(checksum),
        )
        # Compare the derived checksum in constant time; this is the actual authentication check
        # for stored pbkdf2 hashes.
        return hmac.compare_digest(calculated, checksum)

    def _bcrypt_rounds(self, password_hash):
        try:
            return int(password_hash.split('$')[2])
        except (IndexError, ValueError) as exc:
            raise UnknownHashError('Invalid bcrypt hash format') from exc

    def _pbkdf2_rounds(self, password_hash):
        try:
            return int(password_hash.split('$')[2])
        except (IndexError, ValueError) as exc:
            raise UnknownHashError('Invalid pbkdf2_sha256 hash format') from exc


class KAPasswordType(ScalarCoercible, types.TypeDecorator):
    impl = types.VARBINARY(1024)
    cache_ok = True

    def __init__(self, max_length=None, onload=None, **kwargs):
        self.onload = onload
        self.context_kwargs = kwargs
        self._context = None
        self._max_length = max_length or 1024

    @property
    def context(self):
        if self._context is None:
            kwargs = dict(self.context_kwargs)
            if self.onload is not None:
                kwargs.update(self.onload(**kwargs))
            # Delay context construction until first use so Flask config-driven defaults are read
            # from the active app rather than import time.
            self._context = PasswordContext(**kwargs)
        return self._context

    @context.setter
    def context(self, value):
        self._context = value

    @property
    def length(self):
        return self._max_length

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            impl = postgresql.BYTEA(self.length)
        elif dialect.name == 'oracle':
            impl = oracle.RAW(self.length)
        elif dialect.name == 'sqlite':
            impl = sqlite.BLOB(self.length)
        elif dialect.name == 'mssql':
            impl = types.VARCHAR(self.length)
        else:
            impl = types.VARBINARY(self.length)
        return dialect.type_descriptor(impl)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None

        if isinstance(value, PasswordHash):
            if value.secret is not None:
                hashed = self.context.hash(value.secret).encode('utf8')
            else:
                hashed = value.hash
        elif isinstance(value, (str, bytes)):
            hashed = self.context.hash(value).encode('utf8')
        else:
            return value

        # Preserve the existing storage contract: binary on most backends, text on MSSQL.
        if dialect.name == 'mssql':
            return hashed.decode('utf8')

        return hashed

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            value = value.encode('utf8')
        return PasswordHash(value, self.context)

    def _coerce(self, value):
        if value is None:
            return None

        if not isinstance(value, PasswordHash):
            # Scalar assignment such as ``user.password = 'secret'`` should immediately wrap and
            # hash the secret so downstream equality checks use the stored-hash semantics.
            return PasswordHash(self.context.hash(value).encode('utf8'), context=self.context)

        value.context = weakref.proxy(self.context)
        if value.secret is not None:
            value.hash = self.context.hash(value.secret).encode('utf8')
            value.secret = None
        return value

    @property
    def python_type(self):
        return self.impl.type.python_type
