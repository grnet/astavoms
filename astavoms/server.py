# Copyright 2016 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

from flask import Flask, request, make_response, jsonify
import logging

from astavoms.authvoms import M2Crypto
from astavoms.ldapuser import LDAPUser, ldap
from kamaki.clients import ClientError as SynnefoError
from kamaki.clients  import KamakiSSLError

app = Flask(__name__)
logger = logging.getLogger(__name__)

ASTAVOMS_SERVER_SETTINGS=dict()


class AstavomsRESTError(Exception):
    """Template class for Astavoms errors"""
    status_code = None # Must be set

    def __init__(self, message=None, status_code=None, payload=None):
        """ Add some context to the error
            :param message: a user friendly message
            :param status_code: REST status code
            :param payload: (dict) some context for the error
        """
        Exception.__init__(self)
        self.message = message or self.__doc__
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        """Return errors in JSON instead of the default HTML format"""
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


class AstavomsInputIsMissing(AstavomsRESTError):
    """Request is missing data input"""
    status_code = 400 # Bad request


class AstavomsInvalidInput(AstavomsRESTError):
    """Input is missing some elements"""
    status_code = 400 # Bad request


class AstavomsUnauthorizedVOMS(AstavomsRESTError):
    """VOMS Authentication Failed"""
    status_code = 401 # Unauthorized


class AstavomsSynnefoError(AstavomsRESTError):
    """Synnefo Error"""
    status_code = 500 # Internal Server Error

    def __init__(
            self, message=None, status_code=500, payload=dict(), error=None):
        if error:
            payload = payload.update(dict(type=error, error='%s' % error))
            status_code = getattr(
                error, 'status', status_code) or self.status_code
            message = message or 'SNF: %s' % error
        AstavomsRESTError.__init__(self, message, status_code, payload)


@app.errorhandler(AstavomsInputIsMissing)
@app.errorhandler(AstavomsInvalidInput)
@app.errorhandler(AstavomsUnauthorizedVOMS)
@app.errorhandler(AstavomsSynnefoError)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


def log_errors(func):
    def wrap(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if isinstance(e, AstavomsRESTError):
                logger.info('%s %s %s' % (type(e), e.status_code, e.message))
                if e.payload:
                    logger.info('\t%s' % e.payload)
            else:
                logger.info('%s: %s' % (type(e), e))
            raise
    wrap.__name__ = func.__name__
    return wrap


def _check_request_data(voms_credentials):
    """Check voms_to_snf request data and raise appropriate errors
    :param voms_credentials: (dict) {"dn": ..., "cert": ..., "chain": ...}
    :raises AstavomsInputIsMissing: if no voms_credentials
    :raises astavomsInvalidInput: if voms_credentials is invalid
    """
    if not voms_credentials:
        raise AstavomsInputIsMissing()
    expected_keys = ('dn', 'cert', 'chain')
    missing = set(expected_keys) - set(voms_credentials)
    unexpected = set(voms_credentials) - set(expected_keys)
    err_msg, payload = 'Input ', dict()
    if missing:
        err_msg += "is missing keys"
        payload['missing'] = tuple(missing)
    if unexpected:
        err_msg += (' and ' if missing else '') + 'contains unexpected keys'
        payload['unexpected'] = tuple(unexpected)
    if missing or unexpected:
        raise AstavomsInvalidInput(err_msg, payload=payload)


dn_to_cn = lambda dn: dn.split('/')[-1].split('=')[-1]
snf_to_user = lambda snf_user, dn, vo, snf_token: dict(
    uid=snf_user['id'],
    userPassword=snf_token,
    sn=vo,
    mail=snf_user['email'],
    givenName=dn,
    cn=dn_to_cn(dn)
)


@app.route('/authenticate', methods=['POST', ])
@log_errors
def authenticate():
    """POST /authenticate
        X-Auth-Token: <token for authorized snf-EGI application>
        {"dn": ..., "cert": ..., "chain": ...}

        Response:
        201 ACCEPTED or 202 CREATED (if a snf-user was just created)
        {
            "snf:uuid": ..., "snf:token": ..., "snf:project": ...,
            "mail": ..., "serverca": ..., "voname": ...,
            "uri": ..., "server": ..., "version": ...,
            "user": ..., "userca": ..., "serial": ...,
            "fqans": [...], "not_after": ..., "not_before": ...
        }

        Errors:
            TODO
    """
    logger.info('POST /authenticate')
    logger.debug('data: %s' % request.data)

    logger.info('Get VOMS credentials')
    voms_credentials = request.json if request.data else None
    _check_request_data(voms_credentials)

    logger.info('Load settings')
    settings = app.config['ASTAVOMS_SERVER_SETTINGS']
    logger.debug('settings: %s' % settings)
    
    logger.info('Authenticate VOMS user')
    vomsauth = settings['vomsauth']
    cert, chain = voms_credentials['cert'], voms_credentials['chain']
    try:
        voms_user = vomsauth.get_voms_info(cert, chain, verify=False)
    except M2Crypto.X509.X509Error as e:
        raise AstavomsUnauthorizedVOMS()
    logger.debug('VOMS user: %s' % voms_user)

    logger.info('Get Synnefo admin client')
    snf_admin = settings['snf_admin']
    responce_code = 201

    logger.info('Connect to LDAP directory')
    ldap_args = settings['ldap_args']
    logger.debug('LDAP args: %s' % ldap_args)

    try:
        with LDAPUser(**ldap_args) as ldap_user:
            logger.info('Make sure user exists in LDAP')
            dn, vo = voms_user['user'], voms_user['voname']
            user = ldap_user.search_by_voms(dn, vo)

            if not user:
                logger.info('No such user in LDAP, look up in Synnefo')

                snf_uuid = snf_admin.get_uuid([dn, ])
                snf_token = None
                if not snf_uuid:
                    logger.info('No Synnefo user, create a new one')
                    name = dn_to_cn(dn).split(' ')
                    first_name, last_name = name[0], ' '.join(name[1:])
                    created = snf_admin.create_user(
                        username=dn,
                        first_name=first_name,
                        last_name=last_name,
                        affiliation=vo
                    )
                    snf_uuid, snf_token = created['id'], created['auth_token']
                    responce_code = 202

                logger.info('User exists in Synnefo, retrieve & refresh token')
                snf_user = snf_admin.get_user_details(snf_uuid)
                snf_token = snf_token or snf_admin.renew_user_token(snf_uuid)
                logger.debug('Synnefo user: %s' % snf_user)

                logger.info('Store user in LDAP')
                user = snf_to_user(snf_user, dn, vo, snf_token)
                ldap_user.create(
                    snf_uuid=snf_uuid, mail=user['mail'], snf_token=snf_token,
                    cn=dn_to_cn(dn), vo=vo, user_dn =dn)
            else:
                logger.info('Authenticate Synnefo user')
                if not snf_admin.authenticate(user['snf_token']):
                    logger.info('Authentication failed, refresh Synnefo token')
                    snf_token = snf_admin.renew_user_token(snf_uuid)
                    user['userPassword'] = snf_token
                    ldap_user.update_snf_token(user['uid'], snf_token)

            logger.debug('User: %s' % user)
    except SynnefoError as se:
        raise AstavomsSynnefoError(error=se)

    response_data = get_response_dict(user, voms_user)
    return make_response(jsonify(response_data), responce_code)


# For testing
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', help='unsafe', action='store_true')
    parser.add_argument('--host', help='IP or fqdn')
    parser.add_argument('--port', help='port', type=int)
    args = parser.parse_args()
    app.config.from_object(__name__)
    app.run(debug=args.debug, host=args.host, port=args.port)

