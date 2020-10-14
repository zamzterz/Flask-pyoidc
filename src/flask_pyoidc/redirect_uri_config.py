#   Copyright 2020 Samuel Gulliksson
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
import warnings
from urllib.parse import urlparse


class RedirectUriConfig:
    def __init__(self, full_uri, endpoint):
        self.full_uri = full_uri
        self.endpoint = endpoint

    def __eq__(self, other):
        return self.full_uri == other.full_uri and self.endpoint == other.endpoint

    def __str__(self):
        return '(' + self.full_uri + ', ' + self.endpoint + ')'

    def __repr__(self):
        return str(self)

    @classmethod
    def from_config(cls, config):
        if 'OIDC_REDIRECT_URI' in config:
            return cls(*RedirectUriConfig._parse_redirect_uri(config['OIDC_REDIRECT_URI']))

        return cls(*RedirectUriConfig._parse_legacy_config(config))

    @staticmethod
    def _parse_redirect_uri(redirect_uri):
        parsed = urlparse(redirect_uri)
        endpoint = parsed.path.lstrip('/')
        return redirect_uri, endpoint

    @staticmethod
    def _parse_legacy_config(config):
        redirect_domain = config.get('OIDC_REDIRECT_DOMAIN', config.get('SERVER_NAME'))
        if not redirect_domain:
            raise ValueError("'OIDC_REDIRECT_URI' must be configured.")

        scheme = config.get('PREFERRED_URL_SCHEME', 'http')

        warnings.warn(
            "Please use 'OIDC_REDIRECT_URI' to configure the redirect_uri for flask-pyoidc. 'OIDC_REDIRECT_DOMAIN' and 'OIDC_REDIRECT_ENDPOINT' have been deprecated.",
            DeprecationWarning,
            stacklevel=2
        )

        endpoint = config.get('OIDC_REDIRECT_ENDPOINT', 'redirect_uri').lstrip('/')
        full_uri = scheme + '://' + redirect_domain + '/' + endpoint

        return full_uri, endpoint

