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

from astavoms import server, utils

# pidfile = '/var/run/astavoms-server.pid'
pidfile = '/tmp/astavoms-server.pid'
logfile = '/tmp/astavoms-server.log'
logger = utils.logging.getLogger(__name__)
app_kw = dict()


def daemon():
    """Create a daemon process detached from the CLI process"""
    logger.info("Start daemon")
    if os.path.exists(pidfile):
        logger.info("Daemon exists (pid file found)")
        sys.stderr.write("Daemon exists (pid file found)\n")
        sys.exit(0)
    try:
        pid = os.fork()
        if pid > 0:
            sys.stderr.write("Started\n")
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


def status(args=None):
    """Report if daemon is running"""
    try:
        with open(pidfile) as f:
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
                pid, pidfile))
    except IOError as ioe:
        logger.debug(ioe)
        sys.stdout.write("Stopped\n")


def run():
    """Run the service with app_kw arguments"""
    server.app.config.from_object(server)
    server.app.run(**app_kw)


def start(args=None):
    """Start the daemon and run"""
    sys.stderr.write("Starting...\n")
    daemon()
    run()


def stop(args=None):
    """Stop the daemon"""
    sys.stderr.write("Stopping ... ")
    logger.info("Stop the daemon")
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


def cli():
    """Script that starts the server"""
    parser = argparse.ArgumentParser()

    sp = parser.add_subparsers()
    sp_start = sp.add_parser('start', help='Starts %(prog)s daemon')
    sp_start.set_defaults(func=start)

    sp_start.add_argument('--debug',
        help='debug details may be sensitive, do not use in production',
        action='store_true')
    sp_start.add_argument('--host', help='IP or domain name for server')
    sp_start.add_argument('--port',
        help='server will listen to this port', type=int)
    sp_start.add_argument('--ldap-url', help='address of LDAP server')
    sp_start.add_argument('--ldap-admin', help='LDAP admin user name')
    sp_start.add_argument('--ldap-password', help='LDAP admin password')
    sp_start.add_argument('--log-file', help='Full path to log file')

    sp_stop = sp.add_parser('stop',help='Stop %(prog)s daemon')
    sp_stop.set_defaults(func=stop)

    sp_status = sp.add_parser(
        'status', help='Report the status of %(prog)s daemon')
    sp_status.set_defaults(func=status)

    pargs = parser.parse_args()
    pargs.func(pargs)
    args = vars(pargs)

    # Environment variables
    envs = dict(
        debug=os.getenv('ASTAVOMS_SERVER_DEBUG', None),
        host=int(os.getenv('ASTAVOMS_SERVER_HOST', 0)) or None,
        port=int(os.getenv('ASTAVOMS_SERVER_PORT', 0)) or None,
        ldap_url=os.getenv('ASTAVOMS_LDAP_URL', None),
        ldap_admin=os.getenv('ASTAVOMS_LDAP_ADMIN', None),
        ldap_password=os.getenv('ASTAVOMS_LDAP_PASSWORD', None),
        log_file=os.getenv('ASTAVOMS_LOG_FILE', None),
    )

    # Read config file and set defaults
    # TODO manage config file
    confs = dict(
        debug=False,
        host='localhost',
        port=5000,
        ldap_url='ldap://localhost',
        ldap_admin='',
        ldap_password='',
        log_file='/tmp/astavoms-server.log'
    )

    val = lambda k: args.get(k) or envs[k] or confs[k]

    utils.setup_logger(logger, debug=val('debug'), log_file=val('log_file'))

    # Set session settings
    # ldaper = LDAPUser(
    #     ldap_url=val('ldap_url'),
    #     admin=val('ldap_admin'),
    #     password=val('ldap_password'),
    #     base_dn=''
    # )
    # ASTAVOMS_SETTINGS.update(dict(
    #     ldaper=ldaper,
    # ))

    # Run server
    for k in ('debug', 'host', 'port'):
        app_kw[k] = val(k)


# For testing
if __name__ == '__main__':
    cli()