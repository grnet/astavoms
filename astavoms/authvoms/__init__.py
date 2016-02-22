# Copyright 2013-2016 GRNET S.A. All rights reserved.
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

import M2Crypto
import logging

from astavoms.authvoms import voms_helper

logger =  logging.getLogger(__name__)


class VomsError(Exception):
    """VOMS failure with description"""
    errors = {
        0: ('none', 'Unknown error'),
        1: ('nosocket', 'socket problem'),
        2: ('noident', 'cannot identify itself (certificate problem)'),
        3: ('comm', 'server problem'),
        4: ('param', 'wrong parameters'),
        5: ('noext', 'voms extension missing'),
        6: ('noinit', 'initialization error'),
        7: ('time', 'error in time checking'),
        8: ('idcheck', 'user data in extension different from the real'),
        9: ('extrainfo', 'vo name and uri missing'),
        10: ('format', 'wrong data format'),
        11: ('nodata', 'empty extension'),
        12: ('parse', 'parse error'),
        13: ('dir', 'directory error'),
        14: ('sign', 'signature error'),
        15: ('server', 'unidentifiable voms server'),
        16: ('mem', 'memory problems'),
        17: ('verify', 'generic verification error'),
        18: ('type', 'returned data of unknown type'),
        19: ('order', 'ordering different than required'),
        20: ('servercode', 'error from the server'),
        21: ('notavail', 'method not available'),
    }

    def __init__(self, error_code=0):
        self.error_code = error_code if error_code in self.errors else 0
        super(VomsError, self).__init__(self, self.errors[error_code][1])


class VomsAuth:
    """Manage VOMS SSL authentication and retrieve user information"""
    voms_policy = '/etc/snf/voms.json'
    voms_dir = '/etc/grid-security/voms_dir/'
    ca_path = '/etc/grid-security/certificates/'
    voms_api_lib = "/usr/lib/libvomsapi.so.1"

    def __init__(self, **kw):
        """Initialize a VOMS Authentiation module"""
        arg_keys = set(['voms_policy', 'voms_dir', 'ca_path', 'voms_api_lib'])
        for k in arg_keys.intersection(kw):
            setattr(self, k, kw[k])

    def get_voms_info(self, cert_pem, chain_list, verify=True):
        """Extract voms info from ssl_info
        :param cert_pem: (str) user certificate in PEM
        :param chain_list: (list)
        :param verify: (bool) whether to check signature
        :returns: (dict) VOMS info
        """
        try:
            # Verify SSL data
            cert = M2Crypto.X509.load_cert_string(str(cert_pem))
            chain = M2Crypto.X509.X509_Stack()
            for c in chain_list:
                chain.push(M2Crypto.X509.load_cert_string(str(c)))
        except M2Crypto.X509.X509Error as e:
            logger.debug(e)
            raise
       
        with voms_helper.VOMS(
                self.voms_dir, self.ca_path, self.voms_api_lib) as v:
            if not verify:
                v.set_no_verify()
               
            voms_data = v.retrieve(cert, chain)
            if not voms_data:
                err_code = VomsError(error_code=v.error.value)
                logger.debug(err)
                raise err

            attrs = (
                'user', 'userca', 'server', 'serverca',
                'voname',  'uri', 'version', 'serial', )
            d = dict([(attr, getattr(voms_data, attr)) for attr in attrs])

            d['not_before'] = getattr(voms_data, 'date1')
            d['not_after'] = getattr(voms_data, 'date2')
            d['fqans'] = []
            for f in iter(voms_data.fqan):
                if f is None:
                    # A core ensues if loop not broken in time
                    break
                d['fqans'].append(f)

        return d


def test(input_, expected):
    """Test VomsAuth
    :param input_: (str) path to a file with test input in json
    :param expected: (str) path to a file with the expected result
    """
    import json
    with open(input_) as f:
        data = json.load(f)
    va = VomsAuth()
    d = va.get_voms_info(data['cert'], data['chain'], verify=False)
    with open(expected) as f:
        e = json.load(f)
    e_fqans, d_fqans = e.pop('fqans'), d.pop('fqans')
    diff = set(e.items()).symmetric_difference(d.items())
    assert len(diff) == 0, "Dicts not equal, diff: %s" % diff
    diff = set(e_fqans).symmetric_difference(d_fqans)
    assert len(diff) == 0, "Fqans not equal, diff: %s" % diff
    sys.stderr.write('... OK\n')


if __name__ == '__main__':
    """Use main to test the script"""
    import sys
    try:
        input_, expected = sys.argv[1], sys.argv[2]
    except IndexError:
        sys.stderr.write('Usage:\n\t%s input.json expected.json\n')
        sys.exit(1)
    test(input_, expected)
    sys.exit(0)
