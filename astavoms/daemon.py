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
from signal import SIGTERM

from astavoms import utils

# pidfile = '/var/run/astavoms-server.pid'
pidfile = '/tmp/astavoms-server.pid'
logfile = '/tmp/astavoms-server.log'
logger = utils.logging.getLogger(__name__)
utils.setup_logger(logger, debug=True, log_file=logfile)


def daemon():
    """The daemon is decoupled from the service"""
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
    os.umask(0)
    os.chdir('/')
    with open(pidfile, 'w') as f:
        f.write(str(os.getpid()))
    sys.stdin  = file('/dev/null','r')
    sys.stdout = file(logfile,'a+')
    sys.stderr = file(logfile,'a+')
    logger.info("Daemon is up and running")


def run():
    """The actual service"""
    from time import sleep
    while True:
        logger.info("Hello World")
        sleep(2)


def status():
    """Report if daemon is running"""
    try:
        with open(pidfile, 'r') as f:
            sys.stdout.write('Started\n')
            return
    except Exception as e:
        logger.debug("While reading pid file: %s" % e)
    sys.stdout.write("Stopped\n")


def start():
    """Start the daemon and run"""
    sys.stderr.write("Starting...\n")
    daemon()
    run()

def stop():
    """Stop the daemon"""
    sys.stderr.write("Stopping...\n")
    logger.info("Stop the daemon")
    try:
        with open(pidfile, 'r') as f:
            pid = int(f.read().strip())
            os.kill(pid, SIGTERM)
        os.remove(pidfile)
    except Exception as e:
        logger.debug("Failed to stop daemon: %s" % e)
    logger.info("Daemon is now stopped")
    status()


def restart():
    """Restart the daemon"""
    stop()
    start()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        {
            'start': start,
            'stop': stop,
            'restart': restart,
            'status': status,
        }[sys.argv[1]]()
    else:
        sys.stderr.write("Usage: start|stop|restart\n")
