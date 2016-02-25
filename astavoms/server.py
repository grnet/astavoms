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


@app.errorhandler(AstavomsInputIsMissing)
@app.errorhandler(AstavomsInvalidInput)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


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


@app.route('/authenticate', methods=['POST', ])
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

    voms_credentials = request.json if request.data else None
    _check_request_data(voms_credentials)

    # Load settings
    settings = app.config['ASTAVOMS_SETTINGS']
    ldap_args = settings['ldap_args']
    logger.debug('settings: %s' % settings)
    logger.info("settings: %s" % settings)
    
    # VOMS authentication
    #   VOMSAuth must be set in server setup, not here
    #   Get VOMSAuth from Settings
    #   voms_user = VOMSAuth().get_voms_info()
    # LDAP query
    #   with LDAPUser(**ldap_args) as ldap_user:
    #       ...
    # Synnefo authentication
    #   astakos.authenticate(...)
    # Update LDAP
    #   with LDAPUser(**ldap_args) as ldap_user:
    #       ...
    # Respond
    #   ...

    responce_code = 201
    response_data = dict(uuid='sample uuid', token='sample token')
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

