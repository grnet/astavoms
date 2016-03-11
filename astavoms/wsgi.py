import json
import os.path

from astavoms.server import app as application
from astavoms import authvoms, identity, server

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
voms_args = dict([(k, v) for k, v in settings.items() if k in (
    'voms_policy', 'voms_dir', 'ca_path', 'voms_api_lib')])

snf_certs = settings.get('snf_ca_certs', None)
if snf_certs:
    https.patch_with_certs(snf_certs)
elif settings.get('snf_ignore_ssl', None):
    https.patch_ignore_ssl()
print settings['snf_auth_url']
snf_admin = identity.IdentityClient(
    settings['snf_auth_url'], settings['snf_admin_token'])
snf_admin.authenticate()
vo_projects = settings.get('vo_projects', None)

server.ASTAVOMS_SERVER_SETTINGS.update(dict(
    ldap_args=ldap_args,
    vomsauth=authvoms.VomsAuth(**voms_args),
    snf_admin=snf_admin,
    vo_projects=vo_projects
))
application.config.from_object(server)
