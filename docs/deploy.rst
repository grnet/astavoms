Deployment guide
^^^^^^^^^^^^^^^^

This is a guide for deploying ``astavoms`` in a debian or debian-based host.
The service runs with ``gunicorn`` and the http/s connection is mediated by
``apache``. This allows operators to apply established deployment techniques.

There is also a simpler deployment method featuring a daemon and a
Flask-only http server, which is ideal for development and testing. It is not
recommended for secure full scale deployment, though.

Creating a user
===============

For security reasons we'll create a new user with ``sudo`` rights, that we'll
call ``astavomer``.

.. code-block:: console

  # adduser astavomer
  # gpasswd -a astavomer sudo

Install required packages
=========================

.. code-block:: console

  # apt-get update
  # apt-get install python python-pip apache2 git gunicorn python-ldap \
    build-essential libsasl2-dev python-dev libldap2-dev libssl-dev swig \
    libvomsapi1 postgresql postgresql-client postgresql-server-dev-all \
    python-psycopg2

Clone the astavoms repository to a directory of your choice. In this guide we
'll use ``/var/tmp/``

.. code-block:: console

  $ cd /var/tmp
  $ git clone <astavoms repo>
  $ cd astavoms
  $ sudo python setup.py build install


Configuring astavoms
====================

In the ``astavoms`` repo, copy ``astavoms/settings.json.template`` to
``astavoms/settings.json`` and edit to apply your settings.

.. code-block:: console

  $ cp astavoms/settings.json.template astavoms/settings.json
  $ vim astavoms/settings.json
   ...

Some settings are optional (meaning: if not set, they default somewhere), some
are mandatory, as described below

.. code-block:: json

  {

    #  Required settings
    "ldap_url": "ldap://ldap.example.org",
    "ldap_admin": "cn=admin,dc=example,dc=org",
    "ldap_password": "passwd",
    "ldap_base_dn": "ou=users,dc=example,dc=org",
    "snf_auth_url": "https://astakos.synnefo.live/astakos/identity/v2.0",
    "snf_admin_token": "synnefo-admin-token",
    "snf_ca_certs": "/etc/ssl/certs/synnefo_ca.pem",

    #  Settings with default values
    "pool_name": "astavoms",
    "pool_host": "localhost",
    "pool_user": "astavoms",
    "pool_password": "astavoms",
    "vo_projects": "/etc/astavoms/vo_projects.json",
    "disable_voms_verification": false,
    "voms_policy": "/etc/astavoms/voms.json",
    "voms_dir": "/etc/grid-security/vomsdir",
    "ca_path": "/etc/grid-security/certificates",
    "voms_api_lib": "/usr/lib/libvomsapi1",
    "logfile": "/var/log/astavoms/server.log",
    "debug": false
  }

Astavoms runs along with a postgresql database serving as a pool of users.
First, create a database user (change the password and, possibly, the user
and the database name to fit your needs):

.. code-block:: console

  # sudo -u postgres psql
  _# CREATE USER astavoms WITH PASSWORD 'astavoms';
  _# CREATE DATABASE astavoms;
  _# GRANT ALL PRIVILEGES ON DATABASE astavoms TO astavoms;
  # astavoms-pool --dbname astavoms --user astavoms --password astavoms create

To feed the pool with unused accounts, create a CSV file (e.g., "users.csv") of the form::

  example-uuid-1234,user1234@example.org,token-for-user-1234
  example-uuid-5678,user5678@example.org,token-for-user-5678
  example-uuid-9012,user9012@example.org,token-for-user-9012

and feed it to astavoms-pool:

.. code-block:: console

  # astavoms-pool --dbname astavoms --user astavoms --password astavoms push < users.csv

VOMS support requires some extra configuration.

First, install the european grid keys. Go to 
http://repository.egi.eu/category/umd_releases/distribution/umd-3 to get the
key addresses and install all keys like this::

  # wget -q -O - <eugridpma key> | apt-key add -


Now, set up the egi-related repositories and install the certificates:

.. code-block:: bash
  # echo "deb http://repository.egi.eu/sw/production/cas/1/current egi-igtf core" > /etc/apt/sources.list.d/egi-cas.list
  # echo "deb http://repository.egi.eu/sw/production/umd/3/debian/ squeeze main" > /etc/apt/sources.list.d/UMD-3-base.list
  # echo "deb http://repository.egi.eu/sw/production/umd/3/debian/ squeeze-updates main" > /etc/apt/sources.list.d/UMD-3-updates.list
  # echo "deb http://repository.egi.eu/community/software/rocci.cli/4.3.x/releases/ubuntu trusty main" >> /etc/apt/sources.list.d/rocci.list
  # apt-get update
  # apt-get install ca-policy-egi-core fetch-crl
  # fetch-crl

note:: trouble with fetch-crl? Try `fetch-crl -p 20`

Create VOMS mappings:

.. code-blocl:: bash

  # mkdir /etc/astavoms
  # touch /etc/astavoms/voms.json
  # touch /etc/vo_projects.json

The voms.json file should look like this::

  {
    "fedcloud.egi.eu": {
      "tenant": "EGI_FCTF"
    },
    "vo.chain-project.eu": {
      "tenant": "chain"
    },
    "ops": {
      "tenant": "EGI_ops"
    },
   "dteam": {
      "tenant": "dteam"
    }
  }

The vo_projects.json file should map VOs to Synnefo project ids::

  {
      "fedcloud.egi.eu": "3401975725925720527-fwgr3g-2f3",
      "vo.chain-project.eu": "3r0o2hf92h-r2fe3vh92r-23rtg3r",
      "ops": "b665d3b0-c14f-4543-bbb3-42d51bd27162",
      "dteam": "r3i2h2hg2-2r3fetgg3r-3grgew-3eg"
  }

Last but not least, create a log area for astavoms:

.. code-block:: bash

  # mkdir /var/log/astavoms
  # chown astavomer:astavomer /var/log/astavoms

Configuring gunicorn
====================

In order for gunicorn to run the ``astavoms`` application a configuration file
must be created under the directory ``/etc/gunicorn.d/``. We choose to call it
``astavoms`` and here are its contents:

.. code-block:: json

	CONFIG = {
	 'mode': 'wsgi',
	 'working_dir': '/var/tmp/astavoms/astavoms',
	 'python': '/usr/bin/python',
	 'user': 'astavomer',
	 'group': 'www-data',
	 'args': (
	   '--bind=127.0.0.1:8000',
	   '--workers=3',
	   '--timeout=60',
	   '--log-level=INFO',
	   '--log-file=/var/log/astavoms/gunicorn.log',
	   'wsgi'
	 ),
	}

    This will run your flask application using ``gunicorn`` on port ``8000``
    of ``127.0.0.1``. You can change the configuration according to your needs.

Creating SSL certificates
=========================

SSL certificates are required to run the service with SSL support. Make sure
you know their location e.g., ``/etc/ssl/private/astavoms.key`` and
``/etc/ssl/certs/astavoms.pem``.

If you don't have certificates signed by an established authority, you can
always create self-signed ones by running:

.. code-block:: console

  # openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/astavoms.key -out /etc/ssl/certs/astavoms.pem

Configuring apache
==================

In the following, we use ``astavoms.live`` as FQDN. You should use your servers
actual FQDN if you have one configured. If you'd rather skip this step for now,
append the following in ``/etc/hosts``::

  127.0.0.1 astavoms.live


Create an ``apache`` configuration file under the directory
``/etc/apache2/sites-available`` with the name ``astavoms.conf`` that contains::

    <VirtualHost *:80>
      ServerName astavoms.live

      RewriteEngine On
      RewriteRule (.*) https://astavoms.live%{REQUEST_URI}
    </VirtualHost>

Create another ``apache`` configuration file (for ssl) under the directory
``/etc/apache2/sites-available`` with the name ``astavoms-ssl.conf`` that contains::

    <IfModule mod_ssl.c>
      <VirtualHost _default_:443>
        ServerName astavoms.live

        AllowEncodedSlashes On

        RequestHeader set X-Forwarded-Protocol "https"

        <Proxy * >
          Order allow,deny
          Allow from all
        </Proxy>

        SetEnv                proxy-sendchunked
        SSLProxyEngine        off
        ProxyErrorOverride    off

        ProxyPass        / http://localhost:8000/ retry=0
        ProxyPassReverse / http://localhost:8000/

        SSLEngine on
        SSLCertificateFile    /etc/ssl/certs/astavoms.pem
        SSLCertificateKeyFile /etc/ssl/private/astavoms.key
      </VirtualHost>
    </IfModule> 

And finally link the newly created files on sites-enabled and enable some
``apache2`` modules.

.. code-block:: console

  # ln -s /etc/apache2/sites-available/astavoms.conf /etc/apache2/sites-enabled/astavoms.conf
  # ln -s /etc/apache2/sites-available/astavoms-ssl.conf /etc/apache2/sites-enabled/astavoms-ssl.conf
  # a2enmod ssl headers rewrite proxy proxy_http
  # service apache2 restart

.. note:: Make sure the correct apache sites are enabled i.e. astavoms.conf and
  astavoms-ssl.conf, by using ``a2ensite`` and ``a2dissite`` commands. Restart
  apache2 in case of a change.
