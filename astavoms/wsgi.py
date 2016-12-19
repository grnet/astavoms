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

import json
import os.path

from astavoms.server import app as application
from astavoms import authvoms, identity, server, utils

from kamaki.clients.utils import https

SETTINGS_FILE = os.path.abspath('settings.json')

with open(SETTINGS_FILE) as f:
    settings = json.load(f)

ldap_args = dict(
    ldap_url=settings.get('ldap_url'),
    admin=settings.get('ldap_admin'),
    password=settings.get('ldap_password'),
    base_dn=settings.get('ldap_base_dn')
)
pool_args = dict(
    dbname=settings.get('pool_name'),
    host=settings.get('pool_host'),
    user=settings.get('pool_user'),
    password=settings.get('pool_password'),
)
voms_args = dict([(k, v) for k, v in settings.items() if k in (
    'voms_policy', 'voms_dir', 'ca_path', 'voms_api_lib')])

snf_certs = settings.get('snf_ca_certs', None)
if snf_certs:
    https.patch_with_certs(snf_certs)
elif settings.get('snf_ignore_ssl', None):
    https.patch_ignore_ssl()

snf_admin = identity.IdentityClient(
    settings['snf_auth_url'], settings['snf_admin_token'])
snf_admin.authenticate()
vo_projects = settings.get('vo_projects', '/etc/astavoms/vo_projects.json')

server.ASTAVOMS_SERVER_SETTINGS.update(dict(
    ldap_args=ldap_args,
    pool_args=pool_args,
    vomsauth=authvoms.VomsAuth(**voms_args),
    snf_admin=snf_admin,
    vo_projects=vo_projects,
    disable_voms_verification=settings.get('disable_voms_verification'),
    self_url=settings.get('self_url', 'https://127.0.0.1:443'),
))
application.config.from_object(server)
debug = settings.get('debug')
logfile = settings.get('logfile', '/var/log/astavoms/server.log')
utils.setup_logger(server.logger, debug=debug, logfile=logfile)
