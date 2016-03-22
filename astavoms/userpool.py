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

import psycopg2


class Userpool:
    """Context manager to push/pop users against a PostgresQL database"""
    table = 'userpool'

    def __init__(self, **db_info):
        self.db_info = db_info

    def __enter__(self):
        self.conn = psycopg2.connect(
            "dbname='{dbname}' "
            "user='{user}' "
            "host='{host}' "
            "password='{password}'".format(**self.db_info))
        self.curs = self.conn.cursor()
        return self

    def __exit__(self, type, value, traceback):
        self.conn.commit()
        self.conn.close()

    def create_db(self):
        """Create the table in the database"""
        try:
            self.curs.execute(
                'CREATE TABLE {table} ('
                ' uuid varchar(64), UNIQUE(uuid),'
                ' email varchar(64), UNIQUE(email),'
                ' token varchar(64),'
                ' used boolean)'.format(table=self.table))
        except Exception as e:
            self.conn.rollback()
            print "FAILED", e

    def push(self, **user_info):
        """user_info: uuid=..., email=..., token=..."""
        schema = "'{uuid}', '{email}', '{token}', '{used}'"
        try:
            self.curs.execute('INSERT INTO {table} VALUES ({vals})'.format(
                table=self.table, vals=schema.format(**user_info)))
        except Exception as e:
            self.conn.rollback()
            print "FAILED", e

    def pop(self):
        """Pop a user from pool"""
        try:
            self.curs.execute(
                "SELECT uuid, email, token FROM {table} "
                "WHERE used='0' LIMIT 1".format(table=self.table))
            uuid, email, token = self.curs.fetchall()[0]
            self.curs.execute(
                "UPDATE {table} SET used='1' WHERE uuid='{uuid}'".format(
                    table=self.table, uuid=uuid))
            return dict(uuid=uuid, email=email, token=token)
        except Exception as e:
            self.conn.rollback()
            print "FAILED", e

    def update_token(self, uuid, new_token):
        try:
            self.curs.execute(
                "UPDATE {table} SET token='{token}' "
                "WHERE uuid='{uuid}'".format(
                    table=self.table, token=new_token, uuid=uuid))
        except Exception as e:
            self.conn.rollback()
            print "FAILED", e


# with Userpool(
#         dbname='astavoms', user='astavoms',
#         host='localhost', password='asta-voms') as astavoms:
    # astavoms.create_db()
    # astavoms.push(uuid=1, email='lala@lele.org', token='mytoken', used=0)
    # print astavoms.pop()
    # astavoms.update_token(1, 'a grand new token')
