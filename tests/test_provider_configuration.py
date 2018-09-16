import json
import pytest
import responses

from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientRegistrationInfo, ProviderMetadata, \
    ClientMetadata, OIDCData


class TestProviderConfiguration(object):
    PROVIDER_BASEURL = 'https://op.example.com'

    def provider_metadata(self, **kwargs):
        return ProviderMetadata(issuer='', authorization_endpoint='', jwks_uri='', **kwargs)

    def test_missing_provider_metadata_raises_exception(self):
        with pytest.raises(ValueError) as exc_info:
            ProviderConfiguration(client_registration_info=ClientRegistrationInfo())

        exc_message = str(exc_info.value)
        assert 'issuer' in exc_message
        assert 'provider_metadata' in exc_message

    def test_missing_client_metadata_raises_exception(self):
        with pytest.raises(ValueError) as exc_info:
            ProviderConfiguration(issuer=self.PROVIDER_BASEURL)

        exc_message = str(exc_info.value)
        assert 'client_registration_info' in exc_message
        assert 'client_metadata' in exc_message

    @responses.activate
    def test_should_fetch_provider_metadata_if_not_given(self):
        provider_metadata = {
            'issuer': self.PROVIDER_BASEURL,
            'authorization_endpoint': self.PROVIDER_BASEURL + '/auth',
            'jwks_uri': self.PROVIDER_BASEURL + '/jwks'
        }
        responses.add(responses.GET,
                      self.PROVIDER_BASEURL + '/.well-known/openid-configuration',
                      json=provider_metadata)

        provider_config = ProviderConfiguration(issuer=self.PROVIDER_BASEURL,
                                                client_registration_info=ClientRegistrationInfo())
        provider_config.ensure_provider_metadata()
        assert provider_config._provider_metadata['issuer'] == self.PROVIDER_BASEURL
        assert provider_config._provider_metadata['authorization_endpoint'] == self.PROVIDER_BASEURL + '/auth'
        assert provider_config._provider_metadata['jwks_uri'] == self.PROVIDER_BASEURL + '/jwks'

    def test_should_not_fetch_provider_metadata_if_given(self):
        provider_metadata = self.provider_metadata()
        provider_config = ProviderConfiguration(provider_metadata=provider_metadata,
                                                client_registration_info=ClientRegistrationInfo())

        provider_config.ensure_provider_metadata()
        assert provider_config._provider_metadata == provider_metadata

    @responses.activate
    def test_should_register_dynamic_client_if_client_registration_info_is_given(self):
        registration_endpoint = self.PROVIDER_BASEURL + '/register'
        responses.add(responses.POST, registration_endpoint, json={'client_id': 'client1', 'client_secret': 'secret1'})

        provider_config = ProviderConfiguration(
            provider_metadata=self.provider_metadata(registration_endpoint=registration_endpoint),
            client_registration_info=ClientRegistrationInfo())

        extra_args = {'extra_args': 'should be passed'}
        redirect_uris = ['https://client.example.com/redirect']
        provider_config.register_client(redirect_uris, extra_args)
        assert provider_config._client_metadata['client_id'] == 'client1'
        assert provider_config._client_metadata['client_secret'] == 'secret1'
        assert provider_config._client_metadata['redirect_uris'] == redirect_uris

        expected_registration_request = {'redirect_uris': redirect_uris}
        expected_registration_request.update(extra_args)
        assert json.loads(responses.calls[0].request.body.decode('utf-8')) == expected_registration_request

    def test_should_not_register_dynamic_client_if_client_metadata_is_given(self):
        client_metadata = ClientMetadata(client_id='client1',
                                         client_secret='secret1',
                                         redirect_uris=['https://client.example.com/redirect'])
        provider_config = ProviderConfiguration(provider_metadata=self.provider_metadata(),
                                                client_metadata=client_metadata)
        provider_config.register_client([])
        assert provider_config._client_metadata == client_metadata

    def test_should_raise_exception_for_non_registered_client_when_missing_registration_endpoint(self):
        provider_config = ProviderConfiguration(provider_metadata=self.provider_metadata(),
                                                client_registration_info=ClientRegistrationInfo())
        with pytest.raises(ValueError) as exc_info:
            provider_config.register_client([])
        assert 'registration_endpoint' in str(exc_info.value)


class TestOIDCData(object):
    def test_client_secret_should_not_be_in_string_representation(self):
        client_secret = 'secret123456'
        client_metadata = OIDCData(client_id='client1', client_secret=client_secret)
        assert client_secret not in str(client_metadata)
        assert client_secret in repr(client_metadata)

    def test_copy_should_overwrite_existing_value(self):
        data = OIDCData(abc='xyz')
        copy_data = data.copy(qwe='rty', abc='123')
        assert copy_data == {'abc': '123', 'qwe': 'rty'}
