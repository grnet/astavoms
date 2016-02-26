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
import sys
import logging
import argparse
from signal import SIGTERM

from astavoms import server, utils, authvoms, identity

logger = utils.logging.getLogger(__name__)


def daemon(pidfile, logfile):
    """Create a daemon process detached from the CLI process"""
    logger.info("Start daemon")
    if os.path.exists(pidfile):
        logger.info("Daemon exists (pid file found)")
        sys.stderr.write("Daemon exists (pid file found)\n")
        sys.exit(0)
    try:
        pid = os.fork()
        if pid > 0:
            sys.stderr.write("started\n")
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
    sys.stdin  = file('/dev/null','r')
    sys.stdout = file(logfile,'a+')
    sys.stderr = file(logfile,'a+')
    logger.info("Daemon is running")


def status(settings):
    """Report if daemon is running"""
    try:
        with open(settings['pidfile']) as f:
            pid = int(f.read().strip())
        os.kill(int(pid), 0)
        sys.stdout.write('Running ( pid: %s )\n' % pid)
    except ValueError as ve:
        logger.debug(ve)
        sys.stdout.write("Error while reading PID from file:\n\t%s\n" % ve)
    except OSError as oee:
        logger.debug(oee)
        sys.stdout.write(
            "Process %s not running, althought file %s exists\n" % (
                pid, settings['pidfile']))
    except IOError as ioe:
        logger.debug(ioe)
        sys.stdout.write("Stopped\n")


def run(settings):
    """Run the service"""
    ldap_args = dict(
        ldap_url=settings.get('ldap_url'),
        admin=settings.get('ldap_admin'),
        ldap_password=settings.get('ldap_password'),
        base_dn=settings.get('ldap_base_dn')
    )
    voms_args = dict([(k, v) for k, v in settings.items() if k in (
        'voms_policy', 'voms_dir', 'ca_path', 'voms_api_lib')])
    snf_admin = identity.IdentityClient(
        settings['snf_auth_url'], settings['snf_admin_token'])

    server.ASTAVOMS_SERVER_SETTINGS.update(dict(
        ldap_args=ldap_args,
        vomsauth=authvoms.VomsAuth(**voms_args),
        snf_admin=snf_admin
    ))
    server.app.config.from_object(server)
    utils.setup_logger(
        server.logger,
        debug=settings['debug'], logfile=settings['logfile'])
    server.app.run(host=settings.get('host'), port=settings.get('port'))


def start(settings):
    """Start the daemon and run"""
    sys.stderr.write("Starting ... ")
    daemon(pidfile=settings['pidfile'], logfile=settings['logfile'])
    run(settings)


def stop(settings):
    """Stop the daemon"""
    sys.stderr.write("Stopping ... ")
    logger.info("Stop the daemon")
    pidfile = settings['pidfile']
    try:
        with open(pidfile, 'r') as f:
            pid = int(f.read().strip())
            try:
                os.kill(pid, SIGTERM)
            finally:
                os.remove(pidfile)
        logger.info("Daemon is now stopped")
        sys.stderr.write("stopped\n")
    except Exception as e:
        logger.debug("Failed to stop daemon: %s" % e)
        sys.stderr.write('\n\t%s\n' % e)

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

    sp_start = sp.add_parser('start', help='Starts %(prog)s daemon')
    sp_start.set_defaults(func=start, cmd='start')
    sp_start.add_argument('--host', help='IP or domain name for server')
    sp_start.add_argument('--port',
        help='server will listen to this port', type=int)
    sp_start.add_argument('--ldap-url', help='address of LDAP server')
    sp_start.add_argument('--ldap-admin', help='LDAP admin user name')
    sp_start.add_argument('--ldap-password', help='LDAP admin password')
    sp_start.add_argument('--snf-auth-url', help='Synnefo Authentication URL')
    sp_start.add_argument('--snf-admin-token', help='Synnefo admin token')

    sp_stop = sp.add_parser('stop',help='Stop %(prog)s daemon')
    sp_stop.set_defaults(func=stop, cmd='stop')

    sp_restart = sp.add_parser('restart',help='Restart %(prog)s daemon')
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
        host=int(os.getenv('ASTAVOMS_SERVER_HOST', 0)) or None,
        port=int(os.getenv('ASTAVOMS_SERVER_PORT', 0)) or None,
        ldap_url=os.getenv('ASTAVOMS_LDAP_URL', None),
        ldap_admin=os.getenv('ASTAVOMS_LDAP_ADMIN', None),
        ldap_password=os.getenv('ASTAVOMS_LDAP_PASSWORD', None),
        ldap_base_dn=os.getenv('ASTAVOMS_LDAP_BASE_DN', None),
        snf_auth_url=os.getenv('ASTAVOMS_SNF_AUTH_URL', None),
        snf_admin_token=os.getenv('ASTAVOMS_SNF_ADMIN_TOKEN', None),
        logfile=os.getenv('ASTAVOMS_LOGFILE', None),
        pidfile=os.getenv('ASTAVOMS_PIDFILE', None)
    )

    # Read config file and set defaults
    # TODO manage config file
    confs = dict(
        debug=False,
        host='localhost',
        port=5000,
        ldap_url='ldap://localhost',
        ldap_admin='', ldap_password='', ldap_base_dn='',
        snf_auth_url='', snf_admin_token='',
        logfile='/var/run/astavoms-server.log',
        pidfile = '/var/run/astavoms-server.pid',
    )

    val = lambda k: args.get(k) or envs[k] or confs[k]
    utils.setup_logger(logger, debug=val('debug'), logfile=val('logfile'))
    settings = {k: val(k) for k in confs.keys()}

    # Run server
    pargs.func(settings)


# For testing
if __name__ == '__main__':
    cli()