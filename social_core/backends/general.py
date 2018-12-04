#3rd party oauth2 small wrapper function
import hmac
import time
import json
import base64
import hashlib

from ..utils import parse_qs, constant_time_compare, handle_http_errors
from .oauth import BaseOAuth2
from ..exceptions import AuthException, AuthCanceled, AuthUnknownError, \
                         AuthMissingParameter


class GenericOAuth2(BaseOAuth2):
    name = 'generic'
    REDIRECT_STATE_PARAMETER = False
    RETURN_SCOPES_PARAMETER = False
    RESPONSE_TYPE_PARAMETER = False
    SCOPE_SEPARATOR = ','
    AUTHORIZATION_URL = ''
    ACCESS_TOKEN_URL = ''
    USER_DATA_URL = ''
    STATE_PARAMETER = False

    def auth_params(self, state=None):
        params = super(GenericOAuth2, self).auth_params(state)
        params['return_scopes'] = 'true'
        return params

    def authorization_url(self):
        return self.AUTHORIZATION_URL

    def access_token_url(self):
        return self.ACCESS_TOKEN_URL

    def get_user_details(self, response):
        fullname, first_name, last_name = self.get_user_names(
            response.get('name', ''),
            response.get('given_name', ''),
            response.get('family_name', '')
        )
        return {'username': response.get('username', response.get('name')),
                'email': response.get('email', ''),
                'name': fullname,
                'given_name': first_name,
                'family_name': last_name}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        params = self.setting('PROFILE_EXTRA_PARAMS', {})
        params['access_token'] = access_token

        if self.setting('APPSECRET_PROOF', True):
            _, secret = self.get_key_and_secret()
            params['appsecret_proof'] = hmac.new(
                secret.encode('utf8'),
                msg=access_token.encode('utf8'),
                digestmod=hashlib.sha256
            ).hexdigest()

        return self.get_json(self.USER_DATA_URL.format(version=version),
                             params=params)

    def process_error(self, data):
        super(GenericOAuth2, self).process_error(data)
        if data.get('error_code'):
            raise AuthCanceled(self, data.get('error_message') or
                                     data.get('error_code'))

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        self.process_error(self.data)
        if not self.data.get('code'):
            raise AuthMissingParameter(self, 'code')
        state = self.validate_state()
        key, secret = self.get_key_and_secret()
        response = self.request(self.access_token_url(), params={
            'client_id': key,
            'redirect_uri': self.get_redirect_uri(state),
            'client_secret': secret
        })
        try:
            response = response.json()
        except ValueError:
            response = parse_qs(response.text)
        access_token = response['access_token']
        return self.do_auth(access_token, response, *args, **kwargs)

    def process_refresh_token_response(self, response, *args, **kwargs):
        try:
            return response.json()
        except ValueError:
            return parse_qs(response.content)

    def refresh_token_params(self, token, *args, **kwargs):
        client_id, client_secret = self.get_key_and_secret()
        return {
            'exchange_token': token,
            'grant_type': 'exchange_token',
            'client_id': client_id,
            'client_secret': client_secret
        }

    def do_auth(self, access_token, response=None, *args, **kwargs):
        response = response or {}

        data = self.user_data(access_token)

        if not isinstance(data, dict):
            raise AuthUnknownError(self, 'An error ocurred while retrieving '
                                         'users data')

        data['access_token'] = access_token
        if 'expires_in' in response:
            data['expires'] = response['expires_in']

        kwargs.update({'backend': self, 'response': data})
        return self.strategy.authenticate(*args, **kwargs)

    def revoke_token_url(self, token, uid):
        return self.REVOKE_TOKEN_URL

    def revoke_token_params(self, token, uid):
        return {'access_token': token}

    def process_revoke_token_response(self, response):
        return super(GenericOAuth2, self).process_revoke_token_response(
            response
        ) and response.content == 'true'

