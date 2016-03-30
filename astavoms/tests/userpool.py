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

import unittest
import psycopg2
from time import time
from astavoms import userpool


class UserpoolTest(unittest.TestCase):

    def setUp(self):
        self.db_info = dict(
            dbname='astavoms',
            user='astavoms',
            host='localhost',
            password='asta-voms')
        self.old_table = userpool.Userpool.table
        self.table = 'test_{stamp}'.format(stamp=time()).replace('.', '_')
        userpool.Userpool.table = self.table
        with userpool.Userpool(**self.db_info) as pool:
            pool.create_db()

    def tearDown(self):
        try:
            conn = psycopg2.connect(**self.db_info)
            curs = conn.cursor()
            curs.execute('DROP TABLE {table}'.format(table=self.table))
            conn.commit()
            conn.close()
        except Exception as e:
            print '\twarning while droping table {table}: {e}'.format(
                table=self.table, e=e)
        finally:
            userpool.Userpool.table = self.old_table

    def test_00_create_db(self):
        conn = psycopg2.connect(**self.db_info)
        curs = conn.cursor()
        curs.execute('SELECT * FROM {table}'.format(table=self.table))
        self.assertEquals(curs.fetchall(), [])
        conn.commit()
        conn.close()

    def test_05_push(self):
        with userpool.Userpool(**self.db_info) as pool:
            u1 = ('uuid1', 'email1', 'token1', False)
            pool.push(*u1)
        conn = psycopg2.connect(**self.db_info)
        curs = conn.cursor()
        curs.execute('SELECT * FROM {table}'.format(table=self.table))
        self.assertEquals(curs.fetchall(), [u1, ])
        conn.commit()
        conn.close()

    def test_10_list(self):
        with userpool.Userpool(**self.db_info) as pool:
            self.assertEquals(pool.list(), [])
            u1 = ('uuid1', 'email1', 'token1', False)
            pool.push(*u1)
            u2 = ('uuid2', 'email2', 'token2', True)
            pool.push(*u2)
            self.assertEquals(pool.list(), [u1, u2])
            self.assertEquals(pool.list(uuid='uuid1'), [u1, ])
            self.assertEquals(pool.list(used=True), [u2, ])

    def test_15_batch_push(self):
        with userpool.Userpool(**self.db_info) as pool:
            u1 = dict(uuid='uuid1', email='email1', token='token1')
            u2 = dict(uuid='uuid2', email='email2', token='token2')
            u3 = dict(uuid='uuid3', email='email3', token='token3')
            pool.batch_push(u1, u2, u3)
            exp = [set(v + [False, ]) for v in (
                u1.values(), u2.values(), u3.values())]
            self.assertEquals([set(u) for u in pool.list()], exp)

    def test_20_pop(self):
        with userpool.Userpool(**self.db_info) as pool:
            u1 = dict(uuid='uuid1', email='email1', token='token1')
            u2 = dict(uuid='uuid2', email='email2', token='token2')
            u3 = dict(uuid='uuid3', email='email3', token='token3')
            pool.batch_push(u1, u2, u3)
            u = pool.pop()
            self.assertTrue(u in [u1, u2, u3])
            self.assertEquals(
                [set(p) for p in pool.list(used=True)],
                [set(u.values() + [True, ]), ])

    def test_25_update_token(self):
        with userpool.Userpool(**self.db_info) as pool:
            u1 = ('uuid1', 'email1', 'token1', False)
            pool.push(*u1)
            u2 = ('uuid2', 'email2', 'token2', True)
            pool.push(*u2)
            new_token = 'new token'
            pool.update_token(u1[0], u1[1], new_token)
            u1 = (u1[0], u1[1], new_token, u1[3])
            self.assertEquals(set(pool.list()), set([u1, u2]))

    def test_30_batch_update_token(self):
        with userpool.Userpool(**self.db_info) as pool:
            u1 = dict(uuid='uuid1', email='email1', token='token1')
            u2 = dict(uuid='uuid2', email='email2', token='token2')
            u3 = dict(uuid='uuid3', email='email3', token='token3')
            pool.batch_push(u1, u2, u3)
            nt1, nt3 = 'new token 1', 'new token 3'
            u1['token'], u3['token'] = nt1, nt3
            pool.batch_update_token(u1, u3)
            exp = [set(v + [False, ]) for v in (
                u2.values(), u1.values(), u3.values())]
            self.assertEquals([set(u) for u in pool.list()], exp)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(UserpoolTest))
    unittest.TextTestRunner(verbosity=2).run(suite)
