import time

import pytest
from mock import patch

from flask_pyoidc.user_session import UserSession, UninitialisedSession


class TestUserSession(object):
    PROVIDER_NAME = 'test_provider'

    def initialised_session(self, session_storage):
        return UserSession(session_storage, self.PROVIDER_NAME)

    def test_initialising_session_with_existing_user_session_should_preserve_state(self):
        storage = {}
        session1 = UserSession(storage, self.PROVIDER_NAME)
        session1.update()
        assert session1.is_authenticated() is True
        assert session1.current_provider == self.PROVIDER_NAME

        session2 = UserSession(storage, self.PROVIDER_NAME)
        assert session2.is_authenticated() is True
        assert session2.current_provider == self.PROVIDER_NAME

        session3 = UserSession(storage)
        assert session3.is_authenticated() is True
        assert session3.current_provider == self.PROVIDER_NAME

    def test_initialising_session_with_new_provider_name_should_reset_session(self):
        storage = {}
        session1 = UserSession(storage, 'provider1')
        session1.update()
        assert session1.is_authenticated() is True
        session2 = UserSession(storage, 'provider2')
        assert session2.is_authenticated() is False

    def test_unauthenticated_session(self):
        assert self.initialised_session({}).is_authenticated() is False

    def test_authenticated_session(self):
        assert self.initialised_session({'last_authenticated': 1234}).is_authenticated() is True

    def test_should_not_refresh_if_not_supported(self):
        assert self.initialised_session({}).should_refresh() is False

    def test_should_not_refresh_if_authenticated_within_refresh_interval(self):
        refresh_interval = 10
        session = self.initialised_session({'last_authenticated': time.time() + (refresh_interval - 1)})
        assert session.should_refresh(refresh_interval) is False

    def test_should_refresh_if_supported_and_necessary(self):
        refresh_interval = 10
        # authenticated too far in the past
        session_storage = {'last_authenticated': time.time() - (refresh_interval + 1)}
        assert self.initialised_session(session_storage).should_refresh(refresh_interval) is True

    def test_should_refresh_if_supported_and_not_previously_authenticated(self):
        assert self.initialised_session({}).should_refresh(10) is True

    @pytest.mark.parametrize('data', [
        {'access_token': 'test_access_token'},
        {'id_token': {'iss': 'issuer1', 'sub': 'user1', 'aud': 'client1', 'exp': 1235, 'iat': 1234}},
        {'id_token_jwt': 'eyJh.eyJz.SflK'},
        {'userinfo': {'sub': 'user1', 'name': 'Test User'}},
    ])
    @patch('time.time')
    def test_update(self, time_mock, data):
        storage = {}
        auth_time = 1234
        time_mock.return_value = auth_time

        self.initialised_session(storage).update(**data)

        expected_session_data = {'last_authenticated': auth_time, 'current_provider': self.PROVIDER_NAME}
        expected_session_data.update(**data)
        assert storage == expected_session_data

    def test_update_should_use_auth_time_from_id_token_if_it_exists(self):
        auth_time = 1234
        session = self.initialised_session({})
        session.update(id_token={'auth_time': auth_time})
        assert session.last_authenticated == auth_time

    def test_trying_to_update_uninitialised_session_should_throw_exception(self):
        with pytest.raises(UninitialisedSession):
            UserSession(session_storage={}).update()

    def test_clear(self):
        expected_data = {'initial data': 'should remain'}
        session_storage = expected_data.copy()

        session = self.initialised_session(session_storage)
        session.update('access_token', {'sub': 'user1'}, 'eyJh.eyJz.SflK', {'sub': 'user1}'})
        session.clear()

        assert session_storage == expected_data
