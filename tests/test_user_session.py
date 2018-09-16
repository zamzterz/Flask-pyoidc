import time

import pytest

from flask_pyoidc.user_session import UserSession


class TestUserSession(object):
    def test_unauthenticated_session(self):
        session = UserSession({})
        assert not session.is_authenticated()

    def test_authenticated_session(self):
        session = UserSession({'last_authenticated': 1234})
        assert session.is_authenticated()

    def test_should_not_refresh_if_not_supported(self):
        session = UserSession(session_storage={})
        assert not session.should_refresh()

    def test_should_not_refresh_if_authenticated_within_refresh_interval(self):
        refresh_interval = 10
        session = UserSession(session_storage={'last_authenticated': time.time() + (refresh_interval - 1)})
        assert not session.should_refresh(refresh_interval)

    def test_should_refresh_if_supported_and_necessary(self):
        refresh_interval = 10
        session = UserSession({'last_authenticated': time.time() - (refresh_interval + 1)})
        assert session.should_refresh(refresh_interval)

    def test_should_refresh_if_supported_and_not_previously_authenticated(self):
        session = UserSession({})
        assert session.should_refresh(10)

    @pytest.mark.parametrize('data', [
        {'access_token': 'test_access_token'},
        {'id_token': {'iss': 'issuer1', 'sub': 'user1', 'aud': 'client1', 'exp': 1235, 'iat': 1234}},
        {'id_token_jwt': 'eyJh.eyJz.SflK'},
        {'userinfo': {'sub': 'user1', 'name': 'Test User'}},
    ])
    def test_update(self, data):
        storage = {}
        auth_time = 1234

        UserSession(storage).update(auth_time, **data)

        expected_session_data = {'last_authenticated': auth_time}
        expected_session_data.update(**data)
        assert storage == expected_session_data

    def test_clear(self):
        expected_data = {'initial data': 'should remain'}
        session_storage = expected_data.copy()

        session = UserSession(session_storage)
        session.update(time.time(), 'access_token', {'sub': 'user1'}, 'eyJh.eyJz.SflK', {'sub': 'user1}'})
        session.clear()

        assert session_storage == expected_data
