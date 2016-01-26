# Copyright 2015 GRNET S.A. All rights reserved.
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
    """An LDAP manager for VOMS users"""

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

    def search_by_uid(self, userUID, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...})
        """
        query = '(&(objectclass=person)(uid=%s))' % userUID
        return dict(self._search(query, attrlist))

    def search_by_vo(self, user_cn, user_vo, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...})
        """
        query = '(&(objectclass=person)(cn=%s)(sn=%s))' % (user_cn, user_vo)
        return self._search(query, attrlist)

    def search_by_token(self, token, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...})
        """
        query = '(&(objectclass=person)(userpassword=%s))' % token
        return self._search(query, attrlist)

    def delete_user(self, userUID):
        """Remove a user from the LDAP directory
        :raises ldap.NO_SUCH_OBJECT: if this user is not in the LDAP directory
        """
        dn = 'uid=%s,%s' % (userUID, self.base_dn)
        self.con.delete_s(dn)

    def list_users(self, attrlist=[]):
        """
        :return: (dict) of the form dict(dn={...}, ...)
        """
        return self._search('(&(objectclass=person))', attrlist)

    def create(
            self, userUID, certCN, email, token, user_vo, userClientDN,
            userCert=None):
        add_record = [
            ('objectclass', [
                'person', 'organizationalperson', 'inetorgperson', 'pkiuser']),
            ('uid', [userUID]),
            ('cn', [certCN]),
            ('sn', [user_vo]),
            ('userpassword', [token]),
            ('mail', [email]),
            ('givenname', userClientDN),
            ('ou', ['users'])
        ]
        dn = 'uid=%s,%s' % (userUID, self.base_dn)
        self.con.add_s(dn, add_record)

        if userCert:
            cert_der = ssl.PEM_cert_to_DER_cert(userCert)
            mod_attrs = [(ldap.MOD_ADD, 'userCertificate;binary', cert_der)]
            self.con.modify_s(dn, mod_attrs)

    def update_token(self, userUID, newToken):
        dn = 'uid=%s,%s' % (userUID, self.base_dn)
        mod_attrs = [(ldap.MOD_REPLACE, 'userpassword', newToken)]
        self.con.modify_s(dn, mod_attrs)
