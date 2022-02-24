from contextlib import contextmanager


@contextmanager
def listen_to(signal):
    ''' Context Manager that listens to signals and records emissions
    Example:
    with listen_to(user_logged_in) as listener:
        login_user(user)
        # Assert that a single emittance of the specific args was seen.
        listener.assert_heard_one(app, user=user))
        # Of course, you can always just look at the list yourself
        self.assertEqual(1, len(listener.heard))
    '''
    class _SignalsCaught(object):
        def __init__(self):
            self.heard = []

        def add(self, *args, **kwargs):
            ''' The actual handler of the signal. '''
            self.heard.append((args, kwargs))

        def assert_heard_one(self, *args, **kwargs):
            ''' The signal fired once, and with the arguments given '''
            if len(self.heard) == 0:
                raise AssertionError('No signals were fired')
            elif len(self.heard) > 1:
                msg = '{0} signals were fired'.format(len(self.heard))
                raise AssertionError(msg)
            elif self.heard[0] != (args, kwargs):
                msg = 'One signal was heard, but with incorrect arguments: '\
                    'Got ({0}) expected ({1}, {2})'
                raise AssertionError(msg.format(self.heard[0], args, kwargs))

        def assert_heard_none(self, *args, **kwargs):
            ''' The signal fired no times '''
            if len(self.heard) >= 1:
                msg = '{0} signals were fired'.format(len(self.heard))
                raise AssertionError(msg)

    results = _SignalsCaught()
    signal.connect(results.add)

    try:
        yield results
    finally:
        signal.disconnect(results.add)


def oauth_profile(**kwargs):
    base = {
        'domain_filter': 'mycompany.biz',
        'id_field': 'email',
        'oauth_client_kwargs': {
            'name': 'google',
            'client_id': 'my-google-client',
            'client_secret': 'super-secret',
            'server_metadata_url': 'http://mysite/openid-configuration',
            'client_kwargs': {'scope': 'openid email'},
        }
    }
    base.update(**kwargs)
    return base
