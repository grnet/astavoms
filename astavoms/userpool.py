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
import logging
from functools import wraps

logger = logging.getLogger(__name__)


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

    def log_db_errors(func):
        @wraps(func)
        def wrap(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except psycopg2.DatabaseError as db_err:
                self.conn.rollback()
                logger.info(
                    '{err_type}: {e}'.format(err_type=type(db_err), e=db_err))
                raise
        return wrap

    @log_db_errors
    def create_db(self):
        """Create the table in the database"""
        self.curs.execute(
            'CREATE TABLE {table} ('
            ' uuid varchar(64), UNIQUE(uuid),'
            ' email varchar(64), UNIQUE(email),'
            ' token varchar(64),'
            ' used boolean)'.format(table=self.table))

    @log_db_errors
    def push(self, uuid, email, token, used=0):
        """user_info: uuid=..., email=..., token=..."""
        values = "'{uuid}', '{email}', '{token}', '{used}'".format(
            uuid=uuid, email=email, token=token, used=used)
        self.curs.execute('INSERT INTO {table} VALUES ({values})'.format(
            table=self.table, values=values))

    @log_db_errors
    def pop(self):
        """Pop a user from the pool"""
        update_query = (
            "UPDATE {table} t SET used='1' FROM ("
            " SELECT * FROM userpool WHERE used='0' LIMIT 1) pool "
            "WHERE pool.uuid=t.uuid "
            "RETURNING pool.uuid, pool.email, pool.token".format(
                table=self.table))
        self.curs.execute(
            "WITH upd AS ({update_query}) SELECT * FROM upd".format(
                update_query=update_query))
        uuid, email, token = self.curs.fetchall()[0]
        return dict(uuid=uuid, email=email, token=token)

    @log_db_errors
    def update_token(self, uuid, new_token):
        """Update token for an existing (used of unused) account"""
        self.curs.execute(
            "UPDATE {table} SET token='{token}' WHERE uuid='{uuid}'".format(
                table=self.table, token=new_token, uuid=uuid))

    @log_db_errors
    def batch_push(self, *users):
        """users: {uuid=..., email=..., token=...}, ..."""
        schema = "('{uuid}', '{email}', '{token}', '0')"
        values = ','.join([schema.format(**u) for u in users])
        self.curs.execute("INSERT INTO {table} VALUES {values}".format(
            table=self.table, values=values))

    @log_db_errors
    def batch_update_token(self, *users):
        """users: {uuid=..., token=...}, ..."""
        template = "SELECT '{uuid}' as uuid, '{token}' as token"
        data_table = ' UNION '.join([template.format(**u) for u in users])
        self.curs.execute(
            "UPDATE {table} SET token=data_table.token "
            "FROM ({data_table}) AS data_table "
            "WHERE {table}.uuid=data_table.uuid".format(
                table=self.table, data_table=data_table))


# with Userpool(
#         dbname='astavoms', user='astavoms',
#         host='localhost', password='asta-voms') as astavoms:
#     astavoms.create_db()
#     astavoms.push(uuid=5, email='u5@lele.org', token='mytoken5')
#     print astavoms.pop()
#     astavoms.update_token(1, 'a grand new token')
#     astavoms.batch_push(
#         dict(uuid=2, email='u2@lala.org', token='token2'),
#         dict(uuid=3, email='u3@lala.org', token='token3'),
#         dict(uuid=4, email='u4@lala.org', token='token4'),
#     )
#     astavoms.batch_update_token(
#         dict(uuid=2, token='new token 02'),
#         dict(uuid=9, token='new token 04'),
#     )
