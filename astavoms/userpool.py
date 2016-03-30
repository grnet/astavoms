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
import csv
import sys
from functools import wraps

from astavoms.utils import strip_dict

logger = logging.getLogger(__name__)


class UserpoolError(Exception):
    """Userpool error"""


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
        self.curs.execute('CREATE INDEX used_index ON {table}(used)'.format(
            table=self.table))

    @log_db_errors
    def list(self, **filters):
        """List pool users"""
        conditions = ["{k}='{v}'".format(k=k, v=v) for k, v in filters.items()]
        self.curs.execute("SELECT * FROM {table} WHERE {condition}".format(
            table=self.table, condition=' AND '.join(conditions) or "'t'"))
        return self.curs.fetchall()

    @log_db_errors
    def push(self, uuid, email, token, used=0):
        """user_info: uuid=..., email=..., token=..."""
        values = "'{uuid}', '{email}', '{token}', '{used}'".format(
            **strip_dict(dict(uuid=uuid, email=email, token=token, used=used)))
        self.curs.execute('INSERT INTO {table} VALUES ({values})'.format(
            table=self.table, values=values))

    @log_db_errors
    def batch_push(self, *users):
        """users: {uuid=..., email=..., token=...}, ..."""
        schema = "('{uuid}', '{email}', '{token}', '0')"
        values = ','.join([schema.format(**strip_dict(u)) for u in users])
        self.curs.execute("INSERT INTO {table} VALUES {values}".format(
            table=self.table, values=values))

    @log_db_errors
    def pop(self):
        """Pop a user from the pool"""
        update_query = (
            "UPDATE {table} t SET used='1' FROM ("
            " SELECT * FROM {table} WHERE used='0' LIMIT 1) pool "
            "WHERE pool.uuid=t.uuid "
            "RETURNING pool.uuid, pool.email, pool.token".format(
                table=self.table))
        self.curs.execute(
            "WITH upd AS ({update_query}) SELECT * FROM upd".format(
                update_query=update_query))
        uuid, email, token = self.curs.fetchall()[0]
        return dict(uuid=uuid, email=email, token=token)

    @log_db_errors
    def update_token(self, uuid, email, token):
        self.curs.execute(
            "UPDATE {table} SET token='{token}' "
            "WHERE uuid='{uuid}'".format(
                table=self.table, token=token.strip(), uuid=uuid.strip()))

    @log_db_errors
    def batch_update_token(self, *users):
        """users: {uuid=..., email=..., token=...}, ..."""
        template = (
            "SELECT '{uuid}' as uuid, '{email}' as email, '{token}' as token")
        data_table = ' UNION '.join(
            [template.format(**strip_dict(u)) for u in users])
        self.curs.execute(
            "UPDATE {table} SET token=data_table.token "
            "FROM ({data_table}) AS data_table "
            "WHERE {table}.uuid=data_table.uuid".format(
                table=self.table, data_table=data_table))


def create(**db_info):
    """Create a new db"""
    with Userpool(**db_info) as pool:
        pool.create_db()


def push(**db_info):
    """Push empty users in the pool"""
    users = csv.reader(sys.stdin)
    users = [dict(zip(('uuid', 'email', 'token'), u)) for u in users]
    with Userpool(**db_info) as pool:
        if len(users) == 1:
            user = users[0]
            pool.push(**user)
        else:
            pool.batch_push(*users)


def update(**db_info):
    """Update given users with new tokens"""
    users = csv.reader(sys.stdin)
    users = [dict(zip(('uuid', 'email', 'token'), u)) for u in users]
    with Userpool(**db_info) as pool:
        if len(users) == 1:
            user = users[0]
            pool.update_token(**user)
        else:
            pool.batch_update_token(*users)


def _list(db_info, **filters):
    with Userpool(**db_info) as pool:
        for u in pool.list(**filters):
            sys.stdout.write(' , '.join(['{0}'.format(i) for i in u]) + '\n')


def list_unused(**db_info):
    """List unused users"""
    return _list(db_info, used='0')


def list_used(**db_info):
    """List unused users"""
    return _list(db_info, used='1')


def cli():
    """A CLI for managing users"""
    import argparse
    from astavoms.utils import setup_logger

    setup_logger(logger)

    parser = argparse.ArgumentParser()
    sp = parser.add_subparsers()
    parser.add_argument('--dbname', help='Postgress DB name', required=True)
    parser.add_argument('--user', help='Postgres DB user', required=True)
    parser.add_argument(
        '--host', help='default: localhost', default='localhost')
    parser.add_argument('--password', help='User password, default: empty')

    # create
    sp_create = sp.add_parser('create', help='Create new pool (aka database)')
    sp_create.set_defaults(func=create)

    # list unused accounts
    sp_unused = sp.add_parser('unused', help='List unused accounts')
    sp_unused.set_defaults(func=list_unused)

    # list used accounts
    sp_used = sp.add_parser('used', help='List used accounts')
    sp_used.set_defaults(func=list_used)

    # push
    sp_push = sp.add_parser(
        'push', help='Pipe CSV file (uuid,email,token) or type in stdin')
    sp_push.set_defaults(func=push)

    # update
    sp_update = sp.add_parser(
        'update',
        help='Update user token(s).     '
             'Pipe CSV file (uuid, new-token) or type in stdin')
    sp_update.set_defaults(func=update)

    pargs = parser.parse_args()
    pargs.func(
        dbname=pargs.dbname,
        user=pargs.user,
        host=pargs.host,
        password=pargs.password)


if __name__ == '__main__':
    cli()
