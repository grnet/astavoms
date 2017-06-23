# Copyright 2017 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import requests

logger = logging.getLogger(__name__)
requests_log = logging.getLogger("requests.packages.urllib3")


def extract_code(environ):
    """:returns: value of 'code' parameter from a request"""
    prefix = 'code='
    for query in environ.get('QUERY_STRING', '').split('&'):
        if query.startswith(prefix):
            return query[len(prefix):]
    return None


def get_tokens(endpoint, **data):
    """POST https://<auth server>/token
    :endpoint: typically of the form http://.../token
    :data: contains
        :code: code to send in order to get the tokens
        :client_id: check apache2 or mod_auth_oidc configuration to get it
        :client_secret: check apache2 or mod_auth_oidc configuration to get it
        :redirect_uri: required by token API
        :grant_type: default: authorization_code
    :returns: a dict with tokens
    """
    logger.info('POST {}'.format(endpoint))
    logger.debug('data={}'.format(data))
    r = requests.post(endpoint, data=data)
    tokens = r.json()
    logger.debug('tokens: {}'.format(tokens))
    return tokens


def get_user_info(endpoint, tokens):
    """GET https://<auth server>/userinfo
    :endpoint: typically of the form http://.../userinfo
    :tokens: a JWT with access tokens
    """
    logger.info('GET {}'.format(endpoint))
    header = {'Authorization': '{type} {token}'.format(
        type=tokens['token_type'], token=tokens['access_token'])}
    logger.debug('header: {}'.format(header))
    r = requests.get(endpoint, header=header)
    user_info = r.json()
    logger.debug('user info: {}'.format(user_info))
    return user_info
