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

import os
import sys
import argparse
import json
from signal import SIGTERM

from astavoms import server, utils, authvoms, identity
from kamaki.clients.utils import https

logger = utils.logging.getLogger(__name__)


def daemon(pidfile, logfile):
    """Create a daemon process detached from the CLI process"""
    logger.info('Start daemon')
    if os.path.exists(pidfile):
        logger.info('Daemon exists (pid file found)')
        sys.stderr.write('Daemon exists (pid file found)\n')
        sys.exit(0)
    try:
        pid = os.fork()
        if pid > 0:
            sys.stderr.write('started\n')
            sys.exit(0)
    except OSError as e:
        import traceback
        traceback.print_exception(e)
        logger.debug(e)
        sys.exit(1)

    os.setsid()
    os.umask(027)
    os.chdir('/')
    with open(pidfile, 'w') as f:
        f.write(str(os.getpid()))
    sys.stdin = file('/dev/null', 'r')
    sys.stdout = file(logfile, 'a+')
    sys.stderr = file(logfile, 'a+')
    logger.info('Daemon is running')


def status(settings):
    """Report if daemon is running"""
    try:
        with open(settings['pidfile']) as f:
            pid = int(f.read().strip())
        os.kill(int(pid), 0)
        sys.stdout.write('Running ( pid: {pid} )\n'.format(pid=pid))
    except ValueError as ve:
        logger.debug(ve)
        sys.stdout.write(
            'Error while reading PID from file:\n\t{ve}}\n'.format(ve=ve))
    except OSError as oee:
        logger.debug(oee)
        sys.stdout.write(
            'Process {pid} not running, '
            'althought file {pidfile} exists\n'.format(
                pid=pid, pidfile=settings['pidfile']))
    except IOError as ioe:
        logger.debug(ioe)
        sys.stdout.write('Stopped\n')


def run(settings):
    """Run the service"""
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
    vo_projects = settings.get('vo_projects', None)
    if snf_certs:
        https.patch_with_certs(snf_certs)
    elif settings.get('snf_ignore_ssl', None):
        https.patch_ignore_ssl()
    snf_admin = identity.IdentityClient(
        settings['snf_auth_url'], settings['snf_admin_token'])
    snf_admin.authenticate()

    server.ASTAVOMS_SERVER_SETTINGS.update(dict(
        ldap_args=ldap_args,
        pool_args=pool_args,
        vomsauth=authvoms.VomsAuth(**voms_args),
        snf_admin=snf_admin,
        vo_projects=vo_projects,
        disable_voms_verification=settings.get('disable_voms_verification'),
    ))
    server.app.config.from_object(server)
    utils.setup_logger(
        server.logger,
        debug=settings['debug'], logfile=settings['logfile'])
    server.app.run(host=settings.get('host'), port=settings.get('port'))


def start(settings):
    """Start the daemon and run"""
    sys.stderr.write('Starting ... ')
    daemon(pidfile=settings['pidfile'], logfile=settings['logfile'])
    run(settings)


def stop(settings):
    """Stop the daemon"""
    sys.stderr.write("Stopping ... ")
    logger.info('Stop the daemon')
    pidfile = settings['pidfile']
    try:
        with open(pidfile, 'r') as f:
            pid = int(f.read().strip())
            try:
                os.kill(pid, SIGTERM)
            finally:
                os.remove(pidfile)
        logger.info('Daemon is now stopped')
        sys.stderr.write("stopped\n")
    except Exception as e:
        logger.debug('Failed to stop daemon: {e}'.format(e=e))
        sys.stderr.write('\n\t{e}\n'.format(e=e))


def restart(settings):
    """Restart the daemon"""
    stop(settings)
    start(settings)


def cli():
    """Script that starts the server"""
    parser = argparse.ArgumentParser()

    sp = parser.add_subparsers()
    parser.add_argument(
        '--debug', help='log in debug mode', action='store_true')
    parser.add_argument('--logfile', help='Full path to log file')
    parser.add_argument('--pidfile', help='Many pidfiles: multiple daemons')
    parser.add_argument('--config', help='Config file in json')

    sp_start = sp.add_parser('start', help='Starts %(prog)s daemon')
    sp_start.set_defaults(func=start, cmd='start')
    sp_start.add_argument('--host', help='IP or domain name for server')
    sp_start.add_argument(
        '--port', help='server will listen to this port', type=int)
    sp_start.add_argument('--ldap-url', help='address of LDAP server')
    sp_start.add_argument('--ldap-admin', help='LDAP admin user name')
    sp_start.add_argument('--ldap-password', help='LDAP admin password')
    sp_start.add_argument(
        '--pool-name', help='Name of pool (aka DBname), default: astavoms')
    sp_start.add_argument(
        '--pool-host', help='Pool (DB) host (default: localhost)')
    sp_start.add_argument(
        '--pool-user', help='Pool (DB) user name, default: astavoms')
    sp_start.add_argument(
        '--pool-password', help='Pool (DB) user password, default: astavoms')
    sp_start.add_argument('--snf-auth-url', help='Synnefo Authentication URL')
    sp_start.add_argument('--snf-admin-token', help='Synnefo admin token')
    sp_start.add_argument('--vo-projects', help='Path to VO-projects json map')
    sp_start.add_argument('--snf-ca-certs', help='Synnefo Client CA certs')
    sp_start.add_argument('--snf-ignore-ssl', help='Ignore Synnefo Client SSL')
    sp_start.add_argument(
        '--disable-voms-verification', help='Do not check VOMS signature')

    sp_stop = sp.add_parser('stop', help='Stop %(prog)s daemon')
    sp_stop.set_defaults(func=stop, cmd='stop')

    sp_restart = sp.add_parser('restart', help='Restart %(prog)s daemon')
    sp_restart.set_defaults(func=restart, cmd='restart')

    sp_status = sp.add_parser(
        'status', help='Report the status of %(prog)s daemon')
    sp_status.set_defaults(func=status, cmd='status')

    pargs = parser.parse_args()
    args = vars(parser.parse_args([pargs.cmd]))
    args.update(vars(pargs))

    # Environment variables
    envs = dict(
        debug=os.getenv('ASTAVOMS_SERVER_DEBUG', None),
        host=os.getenv('ASTAVOMS_SERVER_HOST', 0) or None,
        port=int(os.getenv('ASTAVOMS_SERVER_PORT', 0)) or None,
        disable_voms_verification=os.getenv(
            'ASTAVOMS_DISABLE_VOMS_VERIFICATION', None),
        ldap_url=os.getenv('ASTAVOMS_LDAP_URL', None),
        ldap_admin=os.getenv('ASTAVOMS_LDAP_ADMIN', None),
        ldap_password=os.getenv('ASTAVOMS_LDAP_PASSWORD', None),
        ldap_base_dn=os.getenv('ASTAVOMS_LDAP_BASE_DN', None),
        pool_name=os.getenv('ASTAVOMS_POOL_NAME', None),
        pool_host=os.getenv('ASTAVOMS_POOL_HOST', None),
        pool_user=os.getenv('ASTAVOMS_POOL_USER', None),
        pool_password=os.getenv('ASTAVOMS_POOL_PASSWORD', None),
        snf_auth_url=os.getenv('ASTAVOMS_SNF_AUTH_URL', None),
        snf_admin_token=os.getenv('ASTAVOMS_SNF_ADMIN_TOKEN', None),
        vo_projects=os.getenv('ASTAVOMS_VO_PROJECTS'),
        snf_ca_certs=os.getenv('ASTAVOMS_SNF_CA_CERTS', None),
        snf_ignore_ssl=os.getenv('ASTAVOMS_SNF_CA_CERTS', None),
        logfile=os.getenv('ASTAVOMS_LOGFILE', None),
        pidfile=os.getenv('ASTAVOMS_PIDFILE', None),
        config=os.getenv('ASTAVOMS_CONFIG', None),
    )

    # Set defaults
    defaults = dict(
        debug=False,
        host='localhost', port=5000,
        disable_voms_verification=False,
        ldap_url='ldap://localhost',
        ldap_admin='', ldap_password='', ldap_base_dn='',
        pool_name='astavoms', pool_host='localhost',
        pool_user='astavoms', pool_password='astavoms',
        snf_auth_url='', snf_admin_token='',
        vo_projects='/etc/astavoms/vo_projects.json',
        snf_ca_certs='', snf_ignore_ssl=False,
        logfile='/var/run/astavoms-server.log',
        pidfile='/var/run/astavoms-server.pid',
        config='astavoms/settings.json',
    )

    # Read config
    config_file = args.get('config') or envs['config'] or defaults['config']
    try:
        with open(config_file) as f:
            confs = json.load(f)
    except Exception as e:
        logger.warning(e)
        sys.stderr.write(
            'W: Failed to open config file {config}\n'
            '\t{err_type}: {e}\n'.format(
                config=config_file, err_type=type(e), e=e))
        sys.stderr.write('\tContinue without a config file\n')
        confs = dict()

    def val(k):
        return args.get(k) or envs[k] or confs.get(k) or defaults[k]

    utils.setup_logger(logger, debug=val('debug'), logfile=val('logfile'))
    settings = {k: val(k) for k in defaults.keys()}

    # Run server
    pargs.func(settings)


# For testing
if __name__ == '__main__':
    cli()
