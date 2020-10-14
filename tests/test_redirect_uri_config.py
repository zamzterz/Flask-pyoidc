import pytest
from flask_pyoidc.redirect_uri_config import RedirectUriConfig


class TestRedirectUriConfig(object):
    LEGACY_CONFIG = {'SERVER_NAME': 'example.com', 'PREFERRED_URL_SCHEME': 'http'}

    def test_legacy_config_defaults(self):
        config = RedirectUriConfig.from_config(self.LEGACY_CONFIG)
        assert config.endpoint == 'redirect_uri'
        assert config.full_uri == 'http://example.com/redirect_uri'

    def test_legacy_config_endpoint(self):
        config = RedirectUriConfig.from_config({'OIDC_REDIRECT_ENDPOINT': '/foo', **self.LEGACY_CONFIG})
        assert config.endpoint == 'foo'

    def test_legacy_config_domain(self):
        config = {
            'OIDC_REDIRECT_DOMAIN': 'other.example.com:6000',  # should be preferred over SERVER_NAME
            **self.LEGACY_CONFIG
        }
        redirect_uri_config = RedirectUriConfig.from_config(config)
        assert redirect_uri_config.full_uri == 'http://other.example.com:6000/redirect_uri'

    def test_redirect_uri_config(self):
        config = {
            'OIDC_REDIRECT_URI': 'https://myexample.com:6000/callback',  # should be preferred over all other config
            'OIDC_REDIRECT_DOMAIN': 'other.example.com:6000',
            **self.LEGACY_CONFIG
        }
        redirect_uri_config = RedirectUriConfig.from_config(config)
        assert redirect_uri_config.full_uri == 'https://myexample.com:6000/callback'
        assert redirect_uri_config.endpoint == 'callback'

    def test_should_raise_if_missing_all_config(self):
        with pytest.raises(ValueError) as exc_info:
            RedirectUriConfig.from_config({})
        assert 'OIDC_REDIRECT_URI' in str(exc_info.value)
