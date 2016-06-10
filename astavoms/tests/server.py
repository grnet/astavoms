# Copyright (C) 2016 GRNET S.A.
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

import unittest
from kamaki.clients import ClientError
import mock
import tempfile
import json

from astavoms import server, identity, authvoms

dn = '/C=org/O=example/CN=Tyler Durden/cn=12345678'
uuid, token, email = 'user-uuid', 'user-token', 'dummy@example.org'
user = (
    '{'
    '"dn": "/C=org/O=example/CN=Tyler Durden/cn=12345678",'
    '"cert": "theF1RSTrule0FfightCLU8isW3doNO7talk@B0U7fightCLU8",'
    '"chain": ['
    '"theS3C0NDrule0FfightCLU8isW3doNO7talk@B0U7fightCLU8",'
    '"the7H1RDrule0FfightCLU8is1FsomeoneS@Y5stop7H3fight15over",'
    '"theF0UR7rule0FfightCLU8is0NLY2GUY5to@fight",'
    '"theF1F7Hrule0FfightCLU8is0N3fight@7a71M3",'
    '"the51X7Hrule0FfightCLU8isN0shirtsN0shoes",'
    '"the53V3N7rule0FfightCLU8isF19H75will90on@5long@5theyH@V3to",'
    '"the3197Hrule0FfightCLU8is1Fthis15your157fightY0Uhave70fight"'
    ']'
    '}'
)
user_kwargs = json.loads(''.join(user))
vo_projects = dict(
    vo1='project-id-for-vo1',
    vo2='project-id-for-vo2',
    vo3='project-id-for-vo3'
)
voms_user = dict(user=dn, voname='vo2')
ldap_user = dict(mail=[email, ], uid=[uuid, ], userPassword=[token, ])
pool_user = dict(uuid=uuid, token=token, email=email)


def iter_deep_equality(this, i1, i2):
    for i, v in enumerate(i1):
        if isinstance(v, dict):
            dict_deep_equality(this, v, i2[i])
        elif isinstance(v, tuple) or isinstance(v, list):
            iter_deep_equality(this, v, i2[i])
        else:
            this.assertEquals(v, i2[i])

def dict_deep_equality(this, d1, d2):
    #  Compare top level keys
    this.assertEquals(d1, d2)
    for k, v in d1.items():
        if isinstance(v, dict):
            dict_deep_equality(this, v, d2[k])
        elif isinstance(v, tuple) or isinstance(v, list):
            iter_deep_equality(this, v, d2[k])
        else:
            this.assertEquals(v, d2[k])

snf_auth_response = {
    "access": {
        "token": {
            "expires": "2016-06-17T14:23:56.883601+00:00", 
            "id": "user-token", 
            "tenant": {
                "id": "user-id", 
                "name": "User Name"
            }
        }, 
        "serviceCatalog": [
            {
                "endpoints_links": [], 
                "endpoints": [
                    {
                        "SNF:uiURL": "https://accounts.example.org/ui", 
                        "versionId": "v1.0", 
                        "region": "default", 
                        "publicURL": "https://accounts.example.org/account/v1.0"
                    }
                ], 
                "type": "account", 
                "name": "astakos_account"
            },
        ], 
        "user": {
            "roles": [
                {
                    "name": "default", 
                    "id": "1"
                }
            ], 
            "roles_links": [], 
            "id": "user-id", 
            "projects": [
                "user-id", 
                "project-id-for-vo2"
            ], 
            "name": "User Name"
        }
    }
}


class FlaskTestClientProxy(object):
    dn = 'SSL CLIENT S DN'
    cert = 'SSL CLIENT CERT'
    chain = ['CERT 1', 'CERT 2', 'CERT 3']
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ['HTTP_SSL_CLIENT_S_DN'] = self.dn
        environ['HTTP_SSL_CLIENT_CERT'] = self.cert
        for i, c in enumerate(self.chain):
            k = 'HTTP_SSL_CLIENT_CERT_CHAIN_{0}'.format(i)
            environ['HTTP_SSL_CLIENT_CERT_CHAIN_1'] = c
        return self.app(environ, start_response)


class LDAPUserMock:
    """Mock class for LDAPUser"""


class UserpoolMock:
    """Mock class for Userpool"""


class AuthenticateTest(unittest.TestCase):

    @mock.patch('kamaki.clients.Client.__init__')
    def setUp(self, client):
        self.vo_projects_file = tempfile.NamedTemporaryFile()
        json.dump(vo_projects, self.vo_projects_file)
        self.vo_projects_file.flush()

        server.app.config['TESTING'] = True
        server.app.config['ASTAVOMS_SERVER_SETTINGS'] = dict(
            vomsauth=authvoms.VomsAuth(),
            snf_admin=identity.IdentityClient('http://example.org', 'token'),
            vo_projects=self.vo_projects_file.name,
            ldap_args=dict(
                ldap_url='ldap://ldap.example.org',
                admin='cn=admin,dc=example,dc=org',
                password='passwd',
                base_dn='ou=users,dc=example,dc=org',),
            pool_args=dict(
                pool_name='astavoms',
                pool_host='localhost',
                pool_user='astavoms',
                pool_password='astavoms',
            ),
        )
        self.app = server.app.test_client()

    def tearDown(self):
        self.vo_projects_file.close()

    def test__check_request_data(self):
        valid = dict(dn='some dn', cert='some cert', chain=['c1', 'c2', 'c3'])
        self.assertEquals(server._check_request_data(valid), None)

        invalids = [
            dict(dn='some dn', chain=['c1', 'c2', 'c3']),
            dict(dn='a dn', cert='some cert', chain=['c2', 'c3'], a=1, b=2),
            dict(cert='some cert', chain='c2, c3'),
        ]
        for case in invalids:
            with self.assertRaises(server.AstavomsInvalidInput):
                server._check_request_data(case)

    @mock.patch('astavoms.identity.IdentityClient.create_user')
    @mock.patch('kamaki.clients.Client.__init__')
    def test_create_snf_user(self, client, create_user):
        snf_admin = identity.IdentityClient(None, None)
        vo = 'EXAMPLE'
        email = 'dummy@example.org'
        server.create_snf_user(snf_admin, dn, vo, email)
        create_user.assert_called_once_with(
            username=email,
            first_name='Tyler',
            last_name='Durden.12345678',
            affiliation=vo)

    @mock.patch('kamaki.clients.Client.__init__')
    def test_enroll_to_project(self, client):
        method = 'astavoms.identity.IdentityClient.enroll_to_project'
        snf_admin = identity.IdentityClient(None, None)
        email = 'dummy@example.org'
        project = 's0me-proj3ct-1d'

        with mock.patch(method) as enroll:
            server.enroll_to_project(snf_admin, email, project)
            enroll.assert_called_once_with(email, project)

        with mock.patch(method, side_effect=ClientError('err', 409)) as enroll:
            server.enroll_to_project(snf_admin, email, project)
            #  User already enrolled, fail but supress the error
            enroll.assert_called_once_with(email, project)

        with mock.patch(method, side_effect=ClientError('err', 404)):
            with self.assertRaises(ClientError):
                server.enroll_to_project(snf_admin, email, project)

    def test_bad_request(self):
        for kw in (dict(data=user), dict()):
            r = self.app.post('/authenticate', **kw)
            assert server.AstavomsInputIsMissing.status_code == r.status_code
            assert server.AstavomsInputIsMissing.__doc__ in r.data

    @mock.patch(
        'astavoms.userpool.Userpool.__exit__')
    @mock.patch(
        'astavoms.userpool.Userpool.__enter__', return_value=UserpoolMock())
    @mock.patch(
        'astavoms.ldapuser.LDAPUser.__exit__')
    @mock.patch(
        'astavoms.ldapuser.LDAPUser.__enter__', return_value=LDAPUserMock())
    @mock.patch(
        'astavoms.identity.IdentityClient.authenticate',
        return_value=snf_auth_response)
    @mock.patch(
        'astavoms.authvoms.VomsAuth.get_voms_info', return_value=voms_user)
    @mock.patch('astavoms.server.logger.debug')
    @mock.patch('astavoms.server.logger.info')
    def test_resolve_user(
            self, info, debug, get_voms_info, authenticate,
            ldapuser, ldapuser_exit, userpool, userpool_exit):
        """Test resolve_user when incoming user exists in LDAP"""
        def search_by_voms(*args, **kwargs):
            return [('ldap uuid', ldap_user)]
        LDAPUserMock.search_by_voms = search_by_voms

        def pop(*args, **kwargs):
            return pool_user
        UserpoolMock.pop = pop

        ret = server.resolve_user(**user_kwargs)
        exp = dict(snf_auth_response)
        exp.update({
            'mail': pool_user['email'],
            'user': dn,
            'voname': 'vo2'
        })
        dict_deep_equality(self, ret, exp)

    @mock.patch('astavoms.server.resolve_user', return_value=snf_auth_response)
    def test_authenticate(self, resolve_user):
        """Test /authenticate"""
        r = self.app.post(
            '/authenticate', data=user, content_type='application/json')
        self.assertEquals(r.status_code, 202)
        data = json.loads(r.data)
        exp = dict(snf_auth_response)
        exp.update({
            'snf:uuid': 'user-id',
            'snf:token': 'user-token',
            'snf:project': 'user-id'
        })
        dict_deep_equality(self, data, snf_auth_response)

    @mock.patch('astavoms.server.resolve_user', return_value=snf_auth_response)
    def test_tokens(self, resolve_user):
        """Test POST /v2.0/tokens"""
        send_data = '{"auth": {"voms": "true"}}'
        env_app = FlaskTestClientProxy(self.app)
        r = env_app.app.post(
            '/v2.0/tokens', data=send_data, content_type='application/json')
        self.assertEquals(r.status_code, 202)

        recv_data = json.loads(r.data)
        exp = dict(snf_auth_response)
        exp.update(voms_user)
        exp.update({
            'snf:uuid': 'user-id',
            'snf:token': 'user-token',
            'snf:project': 'user-id',
            "mail": email,
        })
        dict_deep_equality(self, recv_data, exp)

    @mock.patch(
        'astavoms.identity.IdentityClient.authenticate',
        return_value=snf_auth_response)
    def test_tenants(self, snf_admin):
        """Test POST /v2.0/tenants"""
        headers = {'X-Auth-Token': token}
        r = self.app.post('/v2.0/tenants', headers=headers)
        self.assertEquals(r.status_code, 200)

        snf_admin.assert_called_once_with(token)
        data = json.loads(r.data)
        project = dict(
            id='project-id-for-vo2', name='vo2', description='', enabled=True)
        exp = dict(tenants=[project, ], tenants_links=[])
        dict_deep_equality(self, data, exp)

if __name__ == '__main__':
    unittest.main()
