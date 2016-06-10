# Copyright 2016 GRNET S.A.
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

import unittest

from astavoms import utils

dn = '/C=org/O=example/CN=Tyler Durden/cn=12345678'


class UtilsTest(unittest.TestCase):
    """Test utils methods"""

    def test_strip_dict(self):
        """Test strip_dict"""
        d = dict(a='lala', b='lal a', c='la la ', d=' l ala', e=' l al a ')
        e = dict(a='lala', b='lal a', c='la la', d='l ala', e='l al a')
        r = utils.strip_dict(d)
        self.assertEquals(set(r.items()), set(e.items()))

    def test_dn_to_cn(self):
        """Test dn_to_cn"""
        self.assertEquals(utils.dn_to_cn('/A=a/B=b/CN=user'), 'user')
        self.assertEquals(utils.dn_to_cn('/b=a/a=b/cn=user/c=C/d=D'), 'user')
        self.assertEquals(utils.dn_to_cn(dn), 'Tyler Durden.12345678')

    def test_dn_to_email(self):
        self.assertEquals(
            utils.dn_to_email(dn), 'Tyler_Durden.12345678@example.org')
        self.assertEquals(
            utils.dn_to_email('/C=org/O=exam ple/CN=Tyler Durden'),
            'Tyler_Durden@exam_ple.org')


if __name__ == '__main__':
    unittest.main()
