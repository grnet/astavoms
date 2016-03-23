User pool management
^^^^^^^^^^^^^^^^^^^^

Astavoms makes use of a user pool, which contains the credentials of unused
Synnefo users (uuid, email and token). Whenever a "new" user (meaning, one who
has never visited before) is verified, Astavoms pops an unused account from the
pool and enhances it with the "new" user information.

Setup the database
------------------

Userpool is stored in a postgresql database. As stated in the deployment
instructions, to set up the database:

.. code-block:: console

  $ sudo -u postgres psql
  _# CREATE USER astavoms WITH PASSWORD 'astavoms';
  _# CREATE DATABASE astavoms;
  _# GRANT ALL PRIVILEGES ON DATABASE astavoms TO astavoms;
  $ astavoms-pool --dbname astavoms --user astavoms --password astavoms create

After this step, the database 'astavoms' will contain a relation called
'userpool'.

Push accounts
-------------
When the operators have at their hand a new set of unused Synnefo accounts,
it is easy to push them in the pool. The fastest way for batch pushing is by
dumping all the accounts in a CSV file.

An example is the file 'users.csv' with the following contents::

  example-uuid-1234,user1234@example.org,token-for-user-1234
  example-uuid-5678,user5678@example.org,token-for-user-5678
  example-uuid-9012,user9012@example.org,token-for-user-9012

Feed the file to astavoms-pool:

.. code-block:: console

  # astavoms-pool --dbname astavoms --user astavoms --password astavoms push < users.csv

If it is just one user, use 'echo':

.. code-block:: console

  # echo "example-uuid-6543,user6543@example.org,token-for-user-6543" |\
    astavoms-pool --dbname astavoms --user astavoms --password astavoms push


List accounts
-------------

Typically, operators must periodically check for the availability of unused
accounts, which can be checked by listing with 'unused' and 'used' commands.

In the example, assume that the account example-uuid-1234 is already used by astavoms:

.. code-block:: console

    $ astavoms-pool --dbname astavoms --user astavoms --password astavoms unused
      example-uuid-5678 , user5678@example.org , token-for-user-5678 , False
      example-uuid-9012 , user9012@example.org , token-for-user-9012 , False
      example-uuid-6543 , user6543@example.org , token-for-user-6543 , False
    $ astavoms-pool --dbname astavoms --user astavoms --password astavoms used
      example-uuid-1234 , user1234@example.org , token-for-user-1234 , True
    $

Update tokens
-------------

Periodically the operators may need to update the tokens of some or all of the
pooled accounts. To do that, they need to create a CSV file with 'uuid,token'
pairs, e.g. the file 'users_new_tokens.csv' ::

  example-uuid-1234,new-token-for-user-1234
  example-uuid-5678,new-token-for-user-5678
  example-uuid-9012,new-token-for-user-9012
  example-uuid-6543,new-token-for-user-6543

and feed it to the pool:

.. code-block:: console

    $ astavoms-pool --dbname astavoms --user astavoms --password astavoms \
      update < users_new_tokens.csv

or to update just one token:

.. code-block:: console

    $ echo "example-uuid-6543,new-token-for-user-6543" |\
      astavoms-pool --dbname astavoms --user astavoms --password astavoms update

Using the database
------------------

Operators can apply the above operations directly on the database.

.. code-block:: sql

    $ psql astavoms -U astavoms

    /* Push a new account */
    _# INSERT INTO userpool VALUES (
      'example-uuid-1234',
      'user1234@example.org',
      'new-token-for-user-1234'
      );

    /* List unused accounts */
    _# SELECT * FROM userpool WHERE used=0;

    /* List used accounts */
    _# SELECT * FROM userpool WHERE used=1;
