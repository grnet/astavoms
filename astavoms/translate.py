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

from kamaki.clients import ClientError
from astavoms import vomsdir, identity
from inspect import getmembers, ismethod


class SnfOcciUsers(object):
    """Translate OCCI users to Synnefo users and manage their properties"""

    def __init__(
            self, snf_auth_url, snf_admin_token,
            ldap_url, ldap_user, ldap_password, base_dn,
            ca_cert_file=None):
        self.snf_auth_url, self.snf_admin_token = snf_auth_url, snf_admin_token
        self.snf_admin = identity.IdentityClient(snf_auth_url, snf_admin_token)
        self.snf_admin_id = self.snf_admin.user_info['id']
        self.ldap_conf = dict(
            ldap_url=ldap_url,
            user=ldap_user, password=ldap_password,
            base_dn=base_dn,
            ca_cert_file=ca_cert_file)

    @staticmethod
    def dn_to_dict(user_dn):
        """
        :param user_dn: a string, typically of the form
            /C=<country>/O=<org name>/OU=<domain>/CN=<full user name>
        :returns: a dict from a user_dn, all keys are uppercase
        """
        return dict(map(
            lambda x: (x[0].upper(), x[1]),
            [i.split('=') for i in user_dn.split('/') if i]))

    @staticmethod
    def create_user_email(dn, vo):
        user = SnfOcciUsers.dn_to_dict
        full_name = '' % ''.join(
            [(c if (c.isalpha() or c.isdigit()) else '_') for c in user['CN']])
        vo += '.' if vo else ''
        return '%s%s@%s' % (vo, full_name, user['OU'])

    def get_cached_user(self, dn, vo):
        """
        :returns: (dict) user info from LDAP
        :raises KeyError: if not in LDAP
        """
        cn = self.dn_to_dict(dn)['CN']
        with vomsdir.LDAPUser(**self.ldap_conf) as ldap_user:
            return ldap_user.search_by_vo(cn, vo)[dn]

    def cache_user(self, uuid, email, token, dn, vo, cert=None):
        """
        :returns: (dict) updated user info from LDAP
        """
        cn = self.dn_to_dict(dn)['CN']
        with vomsdir.LDAPUser(**self.ldap_conf) as ldap_user:
            ldap_user.create(uuid, cn, email, token, vo, dn, cert)
            return self.get_cached_user(dn, vo)

    def vo_to_project(self, vo):
        """
        :returns: project with name==vo and owned by admin
        :raises ClientError: 404 if not found
        :raises ClientError: 409 if more than one projects match
        """
        vo_projects = self.get_projects(name=vo, owner=self.snf_admin_id)
        if vo_projects:
            if len(vo_projects) > 1:
                raise ClientError(
                    'More than one projects matching name %s' % vo, 409)
            return vo_projects[0]
        raise ClientError('No projects matching name %s' % vo, 404)

    @staticmethod
    def split_full_name(full_name):
        names = [name for name in full_name.split(' ') if name]
        return names[0], ' '.join(names[1:])

    def get_user_info(self, dn, vo):
        """ If user not cached, attempt to create it
        :returns: (dict) cached user info from LDAP directory
        :raises ClientError: 404 if the project is not found
        :raises ClientError: 409 if more than one projects match, new user
            exists or new user is already enrolled to project
        :raises KeyError: if dn is not formated as expected
        """
        try:
            return self.get_cached_user(dn, vo)
        except KeyError:
            project = self.vo_to_project(vo)
            email = self.create_user_email(dn, vo)
            dn_dict = self.dn_to_dict(dn)
            first, last = self.split_full_name(dn_dict['CN'])
            user = self.snf_admin.create_user(email, first, last, dn_dict['O'])
            self.snf_admin.enroll_member(project['id'], email)
            return self.cache_user(
                user['id'], email, user['auth_token'], dn, vo)

    def add_renew_token(self, cls, user_id):
        """ In case of authentication failure, cls gets a new token and the
            failed method is run again.
        :returns: cls with all its methods wrapped
        """
        cls_methods = [m for m in getmembers(cls) if (
            not m[0].startswith('_')) and ismethod(m[1])]
        for name, method in cls_methods:
            def wrap(*args, **kwargs):
                try:
                    return method(*args, **kwargs)
                except ClientError as ce:
                    if ce.status not in (401, ):
                        raise
                    print 'User', user_id, ':', ce
                    print 'Renew token and retry %s.%s(...)' % (
                        cls.__name__, name)
                    user = self.snf_admin.renew_user_token(user_id)
                    with vomsdir.LDAPUser(**self.ldap_conf) as ldap_user:
                        ldap_user.update_token(user['id'], user['auth_token'])
                    cls.token = user['auth_token']
                    return method(*args, **kwargs)
            wrap.__name__ = name
            cls.__setattr__(name, wrap)
        return cls

    def uuid_from_token(self, token):
        """Lookup token in LDAP dir
        :returns: uuid
        :raises KeyError: if token not found
        """
        with vomsdir.LDAPUser(**self.ldap_conf) as ldap_user:
            r = ldap_user.search_by_token(token, ['uuid', ])
            return r.values()[0]['uid']

