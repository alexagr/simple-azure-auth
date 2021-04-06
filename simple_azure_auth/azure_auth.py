# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, Alex Agranov
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import base64
import functools
import json
import random
import string
import time
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
try:
    from urllib.parse import urlencode, quote
except ImportError:
    from urllib import urlencode, quote

__version__ = "1.0.0"


class AzureAuth:

    def __init__(
            self,
            client_id, tenant_id,
            multi_tenant=False,
            http_client=None,
            verify=True, proxies=None, timeout=10):
        """Create an instance of Azure web application.

        Typical authentication flow is as follows:
        - Login screen contains 'Login with Azure' button.
        - When user presses the button he is redirected to 'auth_url' built via :func:`~build_auth_token()`.
          Application should also store returned 'nonce' value in session data.
        - User is prompted to enter his credentials and perform multi-factor authentication if needed.
        - When authentication is complete POST request is issued to the redirect_url, containing id_token.
        - Application verifies id_token via :func:`~verify_token()`, passing stored 'nonce' value as parameter.
        - (optional) Application verifies roles claims in id_token to determine whether user is allowed
          to access it and what role it should be assigned.
        - Based on the verification result user is allowed or denied access to the application.

        :param str client_id:
            Application (client) ID

        :param str tenant_id:
            Directory (tenant) ID

        :param bool multi_tenant: (optional)
            Allow login for accounts in any organizational directory

        :param http_client: (optional)
            Custom implementation of HTTP client; if not provided requests session instance is used

        :param bool verify: (optional)
            Will be passed to the underlying requests library

        :param str proxies: (optional)
            Will be passed to the underlying requests library

        :param int timeout: (optional)
            Will be passed to the underlying requests library
        """
        self.client_id = client_id
        self.tenant_id = tenant_id

        if multi_tenant:
            self.authority = 'common'
        else:
            self.authority = tenant_id

        if http_client:
            self.http_client = http_client
        else:
            self.http_client = requests.Session()
            self.http_client.verify = verify
            self.http_client.proxies = proxies
            self.http_client.request = functools.partial(
                self.http_client.request, timeout=timeout)

        self.keys = {}
        self.last_keys_refresh = 0
        self._get_keys()

    def build_auth_url(
            self,
            redirect_url):
        """Build authorization URL

        :param str redirect_url:
            Address to return identity token to

        :return: dict data:
            {
                'auth_url': 'https://login.microsoftonline.com...',
                'nonce': '123456...'
            }
        """
        data = {}
        data['nonce'] = ''.join(random.sample(string.ascii_letters, 16))
        data['auth_url'] = 'https://login.microsoftonline.com/' + self.authority + '/oauth2/v2.0/authorize?' + \
            urlencode(
                {
                    'client_id': self.client_id,
                    'response_type': 'id_token',
                    'redirect_uri': redirect_url,
                    'response_mode': 'form_post',
                    'scope': 'openid profile',
                    'nonce': data['nonce']
                }
            )
        return data

    def build_logout_url(
            self,
            redirect_url=None):
        """Build logout URL that logs user out of AD account

        :param str redirect_url: (optional)
            Address to redirect after logout

        :return str logout_url:
            Logout URL that logs user from Active Directory and then redirects him to logout page
        """
        logout_url = 'https://login.microsoftonline.com/' + self.authority + '/oauth2/v2.0/logout'
        if redirect_url:
            logout_url += '?post_logout_redirect_uri=' + quote(redirect_url)
        return logout_url

    @staticmethod
    def _decode_value(v):
        # Decode int from base64 string value
        if isinstance(v, str):
            v = v.encode('utf-8')
        decoded = base64.urlsafe_b64decode(v + b'==')
        return int.from_bytes(decoded, 'big')

    @staticmethod
    def _public_key(n, e):
        # Construct RSA public key from key data
        return RSAPublicNumbers(
            n=AzureAuth._decode_value(n),
            e=AzureAuth._decode_value(e)
        ).public_key(default_backend()).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _get_keys(self):
        # Get keys for token verification
        r = self.http_client.get(
            'https://login.microsoftonline.com/' + self.authority + '/discovery/v2.0/keys')
        if r.status_code == 200:
            self.last_keys_refresh = time.time()
            try:
                self.keys = json.loads(r.content)
            except json.JSONDecodeError:
                pass

    def _refresh_keys(self):
        # Refresh keys for token verification
        if time.time() - self.last_keys_refresh > 60:
            self._get_keys()

    def parse_token(
            self,
            token,
            audience=None,
            nonce=None):
        """Parse token

        This method not only parses the token but also performs its verification.
        JWKS data is fetched from the Azure /keys endpoint to perform signature verification.

        :param str token:
            Encoded token string

        :param str audience: (optional)
            Target audience; if specified, token 'aud' claim is checked against the provided value

        :param str nonce: (optional)
            Nonce value; if specified, token 'nonce' claim is checked against the provided value

        :return dict data:
            - Upon successful token parsing a dict with the following elements:
                {
                    'unverified_header': { 'typ': 'JWT', ... },
                    'payload': { 'aud': 'abc', ...},
                }
            - Upon any failure a dict with 'error' element
        """
        data = {}

        try:
            data['unverified_header'] = jwt.get_unverified_header(token)

            kid = data['unverified_header'].get('kid', '')
            if not any(key['kid'] == kid for key in self.keys.get('keys', {})):
                self._refresh_keys()

            public_key = None
            for key in self.keys.get('keys', {}):
                if key['kid'] == kid:
                    public_key = AzureAuth._public_key(key['n'], key['e'])

            if not public_key:
                data['error'] = 'Cannot find key to verify token signature'
                return data

            data['payload'] = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=audience
            )

            if nonce and data['payload'].get('nonce', '') != nonce:
                data['error'] = 'Wrong nonce value'

        except Exception as e:
            data['error'] = str(e)

        return data

    @staticmethod
    def check_role(
            data,
            role,
            case_insensitive=False):
        """Check role claim in the token data

        :param dict data:
            Token data as returned by :func:`~parse_token()`

        :param str role:
            Role as defined in Azure application configuratin

        :param bool case_insensitive: (optional)
            Perform case insensitive comparison

        :return bool status:
            True is token contains specified role claim; False otherwise
        """
        roles = data.get('payload', {}).get('roles', [])
        return any(r == role or (case_insensitive and r.lower() == role.lower()) for r in roles)
