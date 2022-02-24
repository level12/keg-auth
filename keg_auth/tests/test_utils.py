from keg_auth.libs import get_domain_from_email


def test_email_domain():
    assert get_domain_from_email('foo@bar.baz') == 'bar.baz'
    assert get_domain_from_email('foobar') is None
