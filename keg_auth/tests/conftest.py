import warnings

import pytest

from keg_auth_ta.app import KegAuthTestApp

# Because our tests are in keg_auth.testing, which isn't a test module, pytest won't rewrite the
# assertions by default.
pytest.register_assert_rewrite('keg_auth.testing')

warnings.filterwarnings(
    'error', r"Unicode type received non-unicode bind param value",
    module='sqlalchemy.sql.sqltypes'
)


def pytest_configure(config):
    KegAuthTestApp.testing_prep()
