# Copyright 2015-2016 GRNET S.A. All rights reserved.
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

import ldap
import ssl


class LDAPUser:
    """An LDAP manager for Synnefo-VOMS users"""

    def __init__(self, ldap_url, admin, password, base_dn, ca_cert_file=None):
        """
        :raises ldap.LDAPError: if connection fails
        """
        self.con = ldap.initialize(ldap_url)
        self.base_dn = base_dn

        if ca_cert_file:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_cert_file)
            self.con.start_tls_s()

        self.admin, self.password = admin, password

    def __enter__(self):
        self.con.simple_bind_s(self.admin, self.password)
        return self

    def __exit__(self, type, value, traceback):
        self.con.unbind()

    def _search(self, query, attrlist):
        return self.con.search_s(
            self.base_dn, ldap.SCOPE_SUBTREE, query, attrlist)

    def search_by_snf_uuid(self, snf_uuid, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...})
        """
        query = '(&(objectclass=person)(uid=%s))' % snf_uuid
        return dict(self._search(query, attrlist))

    def search_by_voms(self, dn, vo, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...})
        """
        query = '(&(objectclass=person)(givenName=%s)(sn=%s))' % (str(dn), str(vo))
        return self._search(query, attrlist)

    def search_by_snf_token(self, snf_token, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...})
        """
        query = '(&(objectclass=person)(userpassword=%s))' % snf_token
        return self._search(query, attrlist)

    def delete_user(self, snf_uuid):
        """Remove a user from the LDAP directory
        :raises ldap.NO_SUCH_OBJECT: if this user is not in the LDAP directory
        """
        dn = 'uid=%s,%s' % (snf_uuid, self.base_dn)
        self.con.delete_s(dn)

    def list_users(self, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...}, ...)
        """
        return self._search('(&(objectclass=person))', attrlist)

    def create(self, snf_uuid, snf_token, mail, cn, vo, user_dn, cert=None):
        """Add a user in LDAP directory
        :param snf_uuid: (str) the Synnefo user UUID, part of LDAP user uid
        :param snf_token: (str) the Synnefo user token
        :param mail: (str) e-mail
        :param cn: (str) Human-readable name of the human
        :param vo: (str) Virtual organization this user is affiliated to
        :param user_dn: (str) the user DN, e.g. "/C=ORG/C=EXAMPLE/CN=Real name"
        :param cert: (str) user PEM certificate
        """
        add_record = [
            ('objectclass', [
                'person', 'organizationalperson', 'inetorgperson', 'pkiuser']),
            ('uid', [str(snf_uuid), ]),
            ('cn', [str(cn), ]),
            ('sn', [str(vo), ]),
            ('userpassword', [str(snf_token), ]),
            ('mail', [str(mail), ]),
            ('givenname', str(user_dn)),
            ('ou', ['users', ])
        ]
        dn = 'uid=%s,%s' % (str(snf_uuid), str(self.base_dn))
        self.con.add_s(dn, add_record)

        if cert:
            cert_der = ssl.PEM_cert_to_DER_cert(cert)
            mod_attrs = [(ldap.MOD_ADD, 'userCertificate;binary', cert_der)]
            self.con.modify_s(dn, mod_attrs)

    def update_snf_token(self, snf_uuid, new_snf_token):
        dn = 'uid=%s,%s' % (snf_uuid, self.base_dn)
        mod_attrs = [(ldap.MOD_REPLACE, 'userpassword', str(new_snf_token))]
        self.con.modify_s(dn, mod_attrs)


def test(ldap_url, admin, password, base_dn):
    """Create, query and destroy a user"""
    import os
    import json
    kw = dict(
        snf_uuid='snf-uuid', mail='user@example.org', snf_token='snf-token',
        cn='Bunny Lebowski', vo='vo.example.org',
        user_dn ='/C=ORG/O=EXAMPLE/CN=Bunny Lebowski', cert=None
    )
    uid = 'uid=%s,%s' % (kw['snf_uuid'], base_dn)

    with LDAPUser(ldap_url, admin, password, base_dn) as ldap_user:
        print 'Test LDAPUser.create'
        ldap_user.create(**kw)
        print '... method finished OK'

        print 'Test LDAPUser.search_by_snf_uuid'
        user = ldap_user.search_by_snf_uuid(kw['snf_uuid'])
        assert uid in user, "User not created"
        print '... user has been created'
        ret = user[uid]
        for k, e in (
                ('snf_uuid', 'uid'), ('snf_token', 'userPassword'),
                ('vo', 'sn'), ('mail', 'mail'),
                ('user_dn', 'givenName'), ('cn', 'cn'), ):
            assert kw[k] == ret[e][0], '%s!=%s (%s!=%s)' % (
                k, e, kw[k], ret[e])
        print '... all fields and values are OK'

        print 'Test LDAPUser.update_snf_token'
        new_token = 'new-snf-token'
        ldap_user.update_snf_token(kw['snf_uuid'], new_token)
        print '... method finished'
        user = ldap_user.search_by_snf_token(kw['snf_token'], ['uid', ])
        assert not user, 'Old token still there! %s' % user
        user = ldap_user.search_by_snf_token(new_token, ['uid', ])
        assert kw['snf_uuid'] in user[0][1]['uid'], 'Wrong user!!! %s' % user
        print '... token updated OK'

        print 'Delete user'
        ldap_user.delete_user(kw['snf_uuid'])
        print '... method finished'
        user = ldap_user.search_by_snf_uuid(kw['snf_uuid'])
        assert not user, "User %s still in LDAP" % user
        print '... user is deleted OK'


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('LDAP-URL')
    parser.add_argument('LDAP-admin')
    parser.add_argument('LDAP-password')
    parser.add_argument('base_dn')
    args = parser.parse_args()
    test(
        ldap_url = 'ldap://snf-546717.vm.okeanos.grnet.gr',
        admin = 'cn=admin,dc=okeanos,dc=grnet,dc=gr',
        password = '$occildap$',
        base_dn = 'ou=users,dc=okeanos,dc=grnet,dc=gr'
    )
