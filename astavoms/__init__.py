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

__version__ = '0.1'


from kamaki.clients.astakos import Client, ClientError


class IdentityClient(Client):
    """An Extended Identity Client"""

    def list_users(self):
        """List all users"""

    def create_user(
            self, username, first_name, last_name, affilication,
            metadata=None):
        """Create a new user"""

    def get_user_details(self, user_id):
        """Get user details"""

    def modify_user(
            self,
            username=None,
            first_name=None,
            last_name=None,
            affilication=None,
            password=None,
            email=None,
            metadata=None):
        """Modify User"""

    def activate_user(self, user_id):
        """Activate a user"""

    def deactivate_user(self, user_id):
        """Deactivate a user"""

    def renew_user_token(self, user_id):
        """Renew user authentication token"""


def main():
    import sys
    sys.stdout.write('astavoms kamaki extension v' + __version__ + '\n')
