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

import os
import argparse
from flask import Flask, request, make_response, jsonify
from astavoms.vomsdir import LDAPUser, ldap
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

ASTAVOMS_SETTINGS=dict()


class AstavomsRESTError(Exception):
    """Template class for Astavoms errors"""
    status_code = None # Must be set

    def __init__(self, message, status_code=None, payload=None):
        """ Add some context to the error
            :param message: a user friendly message
            :param status_code: REST status code
            :param payload: (dict) some context for the error
        """
        Exception.__init__(self)
        self.message = message
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


@app.errorhandler(AstavomsInputIsMissing)
@app.errorhandler(AstavomsInvalidInput)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@app.route('/voms2snf', methods=['POST', ])
def voms_to_snf():
    """POST /voms2snf
        X-Auth-Token: ...
        {cn: ..., vo: ...}

        Response:
        201 ACCEPTED or 202 CREATED (if a user was created)
        {uuid: ..., token: ...}

    Test:
        curl -X 'POST' localhost:5000/voms2snf -i \
             -d '{"cn": "user cn", "vo": "user vo"}'

        Errors:
            TODO
    """
    logger.info('POST /voms2snf')
    logger.debug('data: %s' % request.data)

    # Check input
    vo_user = request.json if request.data else None
    if not vo_user:
        raise AstavomsInputIsMissing("Request input is missing")
    expected_keys = ('cn', 'vo')
    unexpected_keys =  (expected_keys)
    for key in expected_keys:
        if key not in vo_user:
            raise AstavomsInvalidInput("Missing '%s' from input" % key)

    # Load settings
    settings = app.config['ASTAVOMS_SETTINGS']
    # ldaper = settings['ldaper']
    logger.debug('settings: %s' % settings)
    
    # TODO Astakos-VOMS algorithm
    # try:
    #     ldap_user = ldaper.search_by_vo(vo_user['cn'], vo_user['vo'])
    # except ldap.NO_SUCH_OBJECT as not_found:
    #     logger.info('User not found')
    #     logger.debug('%s %s' % (type(not_found), not_found))
    #     logger.info('Create user')
    responce_code = 201
    # if ok_user:
    #     if not ok_user['username']:
    #         ok_user = astavoms_create_user(vo_user)
    #         ldap_update(vo_user, ok_user)
    #         response_code = 202
    #     elif not astakos.check_token(ok_user):
    #         ok_user = astakos.update_token(ok_user)
    #         ldap_update(vo_user, ok_user)
    # if not ok_user:
    #     raise USER NOT FOUND or something

    response_data = dict(uuid='sample uuid', token='sample token')
    return make_response(jsonify(response_data), responce_code)


def run_server():
    """Script that starts the server"""
    # CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug',
        help='debug details may be sensitive, do not use in production',
        action='store_true')
    parser.add_argument('--host', help='IP or domain name for server')
    parser.add_argument('--port',
        help='server will listen to this port', type=int)
    parser.add_argument('--ldap-url', help='address of LDAP server')
    parser.add_argument('--ldap-admin', help='LDAP admin user name')
    parser.add_argument('--ldap-password', help='LDAP admin password')
    parser.add_argument('--log-file', help='Full path to log file')
    args = vars(parser.parse_args())

    # Environment variables
    envs = dict(
        debug=os.getenv('ASTAVOMS_SERVER_DEBUG', None),
        host=int(os.getenv('ASTAVOMS_SERVER_HOST', 0)) or None,
        port=int(os.getenv('ASTAVOMS_SERVER_PORT', 0)) or None,
        ldap_url=os.getenv('ASTAVOMS_LDAP_URL', None),
        ldap_admin=os.getenv('ASTAVOMS_LDAP_ADMIN', None),
        ldap_password=os.getenv('ASTAVOMS_LDAP_PASSWORD', None),
        log_file=os.getenv('ASTAVOMS_LOG_FILE', None),
    )

    # Read config file and set defaults
    # TODO manage config file
    confs = dict(
        debug=False,
        host='localhost',
        port=5000,
        ldap_url='ldap://localhost',
        ldap_admin='',
        ldap_password='',
        log_file='astavoms.log'
    )

    val = lambda k: args[k] or envs[k] or confs[k]

    #setup logging
    logger.setLevel(logging.DEBUG)
    detailed_format = logging.Formatter(
        '%(asctime)s %(name)s:%(lineno)d %(levelname)s %(message)s')
    minimal_format = logging.Formatter('%(levelname)s: %(message)s')

    file_handler = logging.FileHandler(val('log_file'))
    file_handler.setLevel(logging.DEBUG if val('debug') else logging.INFO)
    file_handler.setFormatter(detailed_format)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if val('debug') else logging.ERROR)
    console_handler.setFormatter(minimal_format)
    logger.addHandler(console_handler)

    # Set session settings
    # ldaper = LDAPUser(
    #     ldap_url=val('ldap_url'),
    #     admin=val('ldap_admin'),
    #     password=val('ldap_password'),
    #     base_dn=''
    # )
    # ASTAVOMS_SETTINGS.update(dict(
    #     ldaper=ldaper,
    # ))
    from astavoms import server
    app.config.from_object(server)

    # Run server
    app.run(debug=val('debug'), host=val('host'), port=val('port'))


# For testing
if __name__ == '__main__':
    run_server()
