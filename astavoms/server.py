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

from flask import Flask, request, make_response
app = Flask(__name__)


@app.route('/voms2snf', methods=['POST', ])
def voms_to_snf():
    """POST /voms2snf
        X-Auth-Token: ...
        {user_dn: ..., user_vo: ...}

        Response:
        201 ACCEPTED or 202 CREATED (if a user was created)
        {uuid: ..., token: ...}

        Errors:
            TODO 
    """
    vo_user = request.json
    # TODO syntax check
    
    # TODO Astakos-VOMS algorithm
    # ok_user = ldap_get_ok_user(vo_user)
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

    from json import dumps
    res = make_response(dumps(vo_user), responce_code)
    return res

def run_server():
    """Script that starts the server"""
    # CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug',
        help='debug details may be sensitive, do not use in production',
        action='store_true')
    parser.add_argument('--port',
        help='server will listen to this port', type=int)
    args = vars(parser.parse_args())

    # Environment variables
    envs = dict(
        debug=os.getenv('ASTAVOMS_SERVER_DEBUG', None),
        port=int(os.getenv('ASTAVOMS_SERVER_PORT', 0)) or None,
    )

    # Read config file and set defaults
    # TODO manage config file
    confs = dict(
        debug=False,
        port=5000,
    )

    # Run server
    val = lambda k: args[k] or envs[k] or confs[k]
    app.run(debug=val('debug'), port=val('port'))


# For testing
if __name__ == '__main__':
    run_server()
