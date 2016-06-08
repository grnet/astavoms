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

import utittest

from astavoms import utils

class UtilsTest(unittest.TestCase):
	"""Test utils methods"""

	def test_strip_dict(self):
		"""Test strip_dict"""
		d = dict(a='lala', b='lal a', c='la la ', d=' l ala', e=' l al a ')
		e = dict(a='lala', b='lal a', c='la la', d='l ala', e='l al a')
		self.assertEquals(set(d.items()), set(e))

if __name__ == '__main__':
    unittest.main()
