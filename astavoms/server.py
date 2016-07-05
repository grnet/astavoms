# Copyright 2016 GRNET S.A.
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

from flask import Flask, request, make_response, jsonify
import logging
import json
from functools import wraps

from astavoms.authvoms import M2Crypto, VomsError
from astavoms.ldapuser import LDAPUser
from astavoms.userpool import Userpool, UserpoolError
from kamaki.clients import ClientError as SynnefoError
from astavoms import utils

app = Flask(__name__)
logger = logging.getLogger(__name__)

ASTAVOMS_SERVER_SETTINGS = dict()


class AstavomsRESTError(Exception):
    """Template class for Astavoms errors"""
    status_code = None  # Must be set

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
    status_code = 400  # Bad request


class AstavomsInvalidInput(AstavomsRESTError):
    """Input is missing some elements"""
    status_code = 400  # Bad request


class AstavomsInvalidProxy(AstavomsRESTError):
    """Client proxy certificates are not well formated or missing"""
    status_code = 400  # Bad request


class AstavomsUnknownVO(AstavomsRESTError):
    """Virtual Organization not in dictionary"""
    status_code = 400  # Bad request


class AstavomsProjectError(AstavomsRESTError):
    """Failed to enroll user to project"""
    status_code = 400  # Unauthorized


class AstavomsUnauthorizedVOMS(AstavomsRESTError):
    """VOMS Authentication Failed"""
    status_code = 401  # Unauthorized


class AstavomsInvalidToken(AstavomsRESTError):
    """This token does not match with any Astavoms users"""
    status_code = 401  # Unauthorized


class AstavomsSynnefoError(AstavomsRESTError):
    """Synnefo Error"""
    status_code = 500  # Internal Server Error

    def __init__(
            self, message=None, status_code=500, payload=dict(), error=None):
        if error:
            snf_status = getattr(error, 'status', '')
            message = message or 'SNF: {err} {status}'.format(
                err=error, status=snf_status)
            payload = payload.update(dict(
                type=error, error='{0}'.format(error), snf_status=snf_status))
            status_code = snf_status or status_code
        AstavomsRESTError.__init__(self, message, status_code, payload)


@app.errorhandler(AstavomsInputIsMissing)
@app.errorhandler(AstavomsInvalidInput)
@app.errorhandler(AstavomsUnknownVO)
@app.errorhandler(AstavomsProjectError)
@app.errorhandler(AstavomsInvalidProxy)
@app.errorhandler(AstavomsUnauthorizedVOMS)
@app.errorhandler(AstavomsInvalidToken)
@app.errorhandler(AstavomsSynnefoError)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


def log_errors(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if isinstance(e, AstavomsRESTError):
                logger.info('{err_type} {status} {message}'.format(
                    err_type=type(e), status=e.status_code, message=e.message))
                if e.payload:
                    logger.info('\t{0}'.format(e.payload))
            else:
                logger.info('{err_type}: {e}'.format(err_type=type(e), e=e))
            raise
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


def create_snf_user(snf_admin, dn, vo, email, project=None):
    """
    :param snf_admin: (IdentityClient)
    :param dn: (str)
    :param vo: (str)
    :param email: (str)
    :param project: (str) extra project id to enroll user to
    :returns: {'id': ..., 'auth_token': ...}
    """
    name = utils.dn_to_cn(dn).split(' ')
    kw = dict(
        username=email,
        first_name=name[0],
        last_name=' '.join(name[1:]),
        affiliation=vo,
    )
    logger.info(
        'Create SNF user {first_name} {last_name} '
        'of {affiliation} (email: {username} )'.format(**kw))
    return snf_admin.create_user(**kw)


def enroll_to_project(snf_admin, email, project):
    """
    :param email: (str) the SNF username
    :param project: (str) the SNF project id
    """
    try:
        snf_admin.enroll_to_project(email, project)
    except SynnefoError as se:
        status = getattr(se, 'status')
        if status not in (409, ):  # 409: User is already enrolled
            raise
        logger.debug('User is already enrolled')


def resolve_user(dn, cert, chain):
    """Use LDAP and Synnefo to resolve a user from a proxy
    """
    logger.info('Load settings')
    settings = app.config['ASTAVOMS_SERVER_SETTINGS']
    logger.debug('settings: {settings}'.format(settings=settings))

    logger.info('Authenticate VOMS user')
    vomsauth = settings['vomsauth']
    voms_verify = not settings.get('disable_voms_verification')
    try:
        voms_user = vomsauth.get_voms_info(cert, chain, voms_verify)
    except (M2Crypto.X509.X509Error, VomsError) as e:
        raise AstavomsUnauthorizedVOMS(
            payload=dict(type=e, error='{0}'.format(e)))
    logger.debug('VOMS user: {voms}'.format(voms=voms_user))

    logger.info('Check SNF admin credentials')
    snf_admin = settings['snf_admin']
    try:
        snf_admin.authenticate()
    except SynnefoError as se:
        raise AstavomsSynnefoError(
            'SNF admin failed to authenticate themselves', error=se)
    response_data = None

    logger.info('Load mappings of VOs to Synnefo Projects')
    with open(settings['vo_projects']) as f:
        vo_projects = json.load(f)
    logger.debug('VO-projects: {vo_projects}'.format(vo_projects=vo_projects))

    logger.info('Connect to LDAP directory')
    ldap_args = settings['ldap_args']
    logger.debug('LDAP args: {ldap_args}'.format(ldap_args=ldap_args))
    try:
        with LDAPUser(**ldap_args) as ldap_user:
            dn, vo = voms_user['user'], voms_user['voname']

            logger.info('Make sure VO is known')
            try:
                project_id = vo_projects[vo]
            except KeyError:
                raise AstavomsUnknownVO('Unknown VO: {vo}'.format(vo=vo))

            logger.info('Make sure user exists in LDAP')
            user = ldap_user.search_by_voms(dn, vo)
            logger.debug('LDAP User: {user}'.format(user=user))

            pool_args = settings['pool_args']
            logger.debug('Pool args: {0}'.format(pool_args))

            if not user:
                logger.info('No such user in LDAP, pop from pool')
                try:
                    with Userpool(**pool_args) as pool:
                        user = pool.pop()
                    snf_uuid, snf_token = user['uuid'], user['token']
                    email = user['email']
                except UserpoolError as upe:
                    logger.info('Failed to pop from user pool')
                    logger.debug('Userpool error: {0}'.format(upe))
                    logger.info('Create user')
                    email = utils.dn_to_email(dn)
                    try:
                        snf_uuid = snf_admin.get_client().get_uuid(email)
                        logger.info('SNF user exists, renew token')
                        snf_user = snf_admin.renew_user_token(snf_uuid)
                    except SynnefoError as se:
                        if getattr(se, 'status') not in (404, 500, ):
                            # AstakosClient.get_uuid returns 500
                            raise
                        logger.debug('SNF: {err} {status}'.format(
                            err=se, status=getattr(se, 'status')))
                        logger.info('SNF user not found')
                        snf_user = create_snf_user(
                            snf_admin, pool_args, dn, vo, email, project_id)
                    snf_uuid = snf_user['id']
                    snf_token = snf_user['auth_token']
                logger.info('Store user in LDAP')
                ldap_user.create(
                    snf_uuid=snf_uuid, snf_token=snf_token, mail=email,
                    cn=utils.dn_to_cn(dn), vo=vo, user_dn=dn)
            else:
                logger.info('Authenticate Synnefo User')
                user = user[0][1]
                email = user['mail'][0]
                snf_uuid = user['uid'][0]
                snf_token = user['userPassword'][0]
                with Userpool(**pool_args) as pool:
                    user = pool.list(uuid=snf_uuid)[0]
                if user[2] != snf_token:
                    snf_token = user[2]
                    ldap_user.update_snf_token(snf_uuid, snf_token)
                try:
                    response_data = snf_admin.authenticate(snf_token)
                except SynnefoError as se:
                    status = getattr(se, 'status')
                    if status not in (401, ):
                        raise
                    logger.debug('SNF: {error} {status}'.format(
                        error=se, status=status))
                    logger.info('Authentication failed, refresh SNF token')
                    try:
                        snf_user = snf_admin.renew_user_token(snf_uuid)
                        snf_token = snf_user['auth_token']
                        logger.info('Update ldap with new token')
                        ldap_user.update_snf_token(snf_uuid, snf_token)
                    except SynnefoError as no_user:
                        status = getattr(no_user, 'status')
                        logger.debug('SNF: {error} {status}'.format(
                            error=no_user, status=status))
                        logger.info('SNF: user not found')
                        raise

            if project_id:
                logger.info('Enroll user to project')
                logger.debug(
                    'Project id: {project}'.format(project=project_id))
                enroll_to_project(snf_admin, email, project_id)

    except SynnefoError as se:
        raise AstavomsSynnefoError(error=se)

    logger.info('Compile response data')
    response_data = response_data or snf_admin.authenticate(snf_token)
    response_data['access']['token']['tenant']['id'] = project_id
    response_data['access']['token']['tenant']['name'] = vo
    response_data.update(voms_user)
    logger.debug('Response data: {data}'.format(data=response_data))
    response_data['mail'] = email
    return response_data


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
    """
    logger.info('POST /authenticate')
    logger.debug('data: {data}'.format(data=request.data))

    logger.info('Get VOMS credentials')
    voms_credentials = request.json if request.data else None
    _check_request_data(voms_credentials)

    r = resolve_user(**voms_credentials)

    snf_user, snf_token = r['access']['user'], r['access']['token']
    r.update({
        'snf:uuid': snf_user['id'],
        'snf:token': snf_token['id'],
        'snf:project': snf_token['tenant']['id'],
    })
    return make_response(jsonify(r), 202)


def get_voms_proxy(environ):
    """Extract VOMS proxy from the WSGI environment
    :returns: SSL_CLIENT_S_DN, SSL_CLIENT_CERT, [SSL_CLIENT_CERT_CHAIN_0, ...]
    """
    dn = request.environ.get('HTTP_SSL_CLIENT_S_DN')
    logger.debug("... dn: {0}".format(dn))
    cert = request.environ.get('HTTP_SSL_CLIENT_CERT')
    logger.debug("... cert: {0}".format(cert))
    chain = [v for k, v in request.environ.iteritems() if k.startswith(
        'HTTP_SSL_CLIENT_CERT_CHAIN_')]
    logger.debug("... chain: {0}".format(chain))
    return dn, cert, chain


@app.route('/v2.0/tokens', methods=['POST', ])
@log_errors
def tokens():
    """POST /v2.0/tokens
    Environ:
        SSL_CLIENT_S_DN: ...
        SSL_CLIENT_CERT: ...
        SSL_CLIENT_CERT_CHAIN_*: ...
    Data:
        {"auth": {"voms": "true"}}

    Responses:
        202 ACCEPTED  {astakos response + voms information}
        401 NOT AUTHORISED
        400 BAD REQUEST
    """
    logger.info('POST /v2.0/tokens')
    if not request.data:
        raise AstavomsInputIsMissing()

    logger.debug('Headers: {0}'.format(request.headers))

    data = request.json
    logger.debug('data: {0}'.format(data))
    if not all([data, "auth" in data, "voms" in data["auth"], data["auth"]]):
        raise AstavomsInvalidInput()

    logger.info("Get client certificate data")
    try:
        dn, cert, chain = get_voms_proxy(request.environ)
    except Exception as e:
        raise AstavomsInvalidProxy(payload=dict(type=e, error='{0}'.format(e)))

    r = resolve_user(dn, cert, chain)
    return make_response(jsonify(r), 202)


@app.route('/v2.0/tenants', methods=['POST', ])
@log_errors
def tenants():
    """POST /v2.0/tenants
    Headers:
        X-Auth-Token: ...

    Responses:
        200 OK {
            "tenants": [{
                "id": ...,
                "name": ...,
                "description": ...,
                "enabled": true},
                ...],
            "tenants_links": []
            }
        400 BAD REQUEST
        401 NOT AUTHORISED
        404 NOT FOUND (Token not found)
    """
    logger.info('POST /v2.0/tenants')
    if not request.data:
        raise AstavomsInputIsMissing()

    data = request.json
    logger.debug('data: {0}'.format(data))
    if not all([
            data, 'auth' in data,
            'voms' in data['auth'], data['auth'],
            'tenantName' in data['auth']]):
        raise AstavomsInvalidInput()

    logger.info('Load settings')
    settings = app.config['ASTAVOMS_SERVER_SETTINGS']
    logger.debug('settings: {settings}'.format(settings=settings))

    logger.info('Get token from X-Auth-Token header')
    token = request.headers.get('X-Auth-Token')
    if token:
        logger.info('Authenticate token and get user information')
        snf_admin = settings['snf_admin']
        snf_user = snf_admin.authenticate(token)
    else:
        logger.info('No X-Auth-Token header, resolve from client proxy')
        try:
            dn, cert, chain = get_voms_proxy(request.environ)
        except Exception:
            raise AstavomsInvalidInput(
                'X-Auth-token header or client proxy required')
        snf_user = resolve_user(dn, cert, chain)
    logger.debug('SNF user: {user}'.format(user=snf_user))
    user_projects = snf_user['access']['user']['projects']

    logger.info('Load mappings of VOs to Synnefo Projects')
    with open(settings['vo_projects']) as f:
        vo_projects = json.load(f)
    logger.debug('VO-projects: {vo_projects}'.format(vo_projects=vo_projects))

    tenants = []
    for name, project_id in vo_projects.items():
        #  ?Check if name == data['tenantName']
        if project_id in user_projects:
            #  TODO: resolve description
            tenants.append(dict(
                id=project_id, name=name, enabled=True, description=''))

    response_code = 200
    response_data = dict(tenants=tenants, tenants_links=[])
    return make_response(jsonify(response_data), response_code)


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
