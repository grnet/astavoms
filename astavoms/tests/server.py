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
vo_projects = dict(
    vo1='project-id-for-vo1',
    vo2='project-id-for-vo2',
    vo3='project-id-for-vo3'
)
voms_user = dict(user=dn, voname='vo2')
ldap_user = dict(mail=[email, ], uid=[uuid, ], userPassword=[token, ])
pool_user = dict(uuid=uuid, token=token, email=email)


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

    def test_dn_to_cn(self):
        self.assertEquals(server.dn_to_cn('/A=a/B=b/CN=user'), 'user')
        self.assertEquals(server.dn_to_cn('/b=a/a=b/cn=user/c=C/d=D'), 'user')
        self.assertEquals(server.dn_to_cn(dn), 'Tyler Durden.12345678')

    def test_phrase_to_str(self):
        for phrase, expected in (
                ('simple', 'simple'), ('with space', 'with_space'),
                (' preceding space', 'preceding_space'),
                ('trailing space ', 'trailing_space'),
                ('multiple   spaces', 'multiple___spaces'),
                ('  This is_a phrase   . ', 'This_is_a_phrase___.')):
            self.assertEquals(server.phrase_to_str(phrase), expected)

    def test_dn_to_email(self):
        self.assertEquals(
            server.dn_to_email(dn), 'Tyler_Durden.12345678@example.org')
        self.assertEquals(
            server.dn_to_email('/C=org/O=exam ple/CN=Tyler Durden'),
            'Tyler_Durden@exam_ple.org')

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
    @mock.patch('astavoms.identity.IdentityClient.authenticate')
    @mock.patch(
        'astavoms.authvoms.VomsAuth.get_voms_info', return_value=voms_user)
    @mock.patch('astavoms.server.logger.debug')
    @mock.patch('astavoms.server.logger.info')
    def test_authenticate_new_user(
            self, info, debug, get_voms_info, authenticate,
            ldapuser, ldapuser_exit, userpool, userpool_exit):
        """When incoming user is not in LDAP"""
        def search_by_voms(*args, **kwargs):
            return None
        LDAPUserMock.search_by_voms = search_by_voms

        def pop(*args, **kwargs):
            return pool_user
        UserpoolMock.pop = pop

        r = self.app.post(
            '/authenticate', data=user, content_type='application/json')
        ret = json.loads(r.data)
        exp = {
            'mail': pool_user['email'],
            'snf:project': vo_projects['vo2'],
            'snf:token': pool_user['token'],
            'snf:uuid': pool_user['uuid'],
            'user': dn,
            'voname': 'vo2'
        }
        self.assertEquals(set(ret.items()), set(exp.items()))
        self.assertEquals(r.status_code, 201)

    @mock.patch(
        'astavoms.userpool.Userpool.__exit__')
    @mock.patch(
        'astavoms.userpool.Userpool.__enter__', return_value=UserpoolMock())
    @mock.patch(
        'astavoms.ldapuser.LDAPUser.__exit__')
    @mock.patch(
        'astavoms.ldapuser.LDAPUser.__enter__', return_value=LDAPUserMock())
    @mock.patch('astavoms.identity.IdentityClient.authenticate')
    @mock.patch(
        'astavoms.authvoms.VomsAuth.get_voms_info', return_value=voms_user)
    @mock.patch('astavoms.server.logger.debug')
    @mock.patch('astavoms.server.logger.info')
    def test_authenticate_existing_user(
            self, info, debug, get_voms_info, authenticate,
            ldapuser, ldapuser_exit, userpool, userpool_exit):
        """When incoming user exists in LDAP"""
        def search_by_voms(*args, **kwargs):
            return ldap_user
        LDAPUserMock.search_by_voms = search_by_voms

        def pop(*args, **kwargs):
            return pool_user
        UserpoolMock.pop = pop

        r = self.app.post(
            '/authenticate', data=user, content_type='application/json')
        ret = json.loads(r.data)
        exp = {
            'mail': pool_user['email'],
            'snf:project': vo_projects['vo2'],
            'snf:token': pool_user['token'],
            'snf:uuid': pool_user['uuid'],
            'user': dn,
            'voname': 'vo2'
        }
        self.assertEquals(set(ret.items()), set(exp.items()))
        self.assertEquals(r.status_code, 201)


if __name__ == '__main__':
    unittest.main()
