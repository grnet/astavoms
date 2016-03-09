Deployment guide
^^^^^^^^^^^^^^^^

This is a guide for deploying astavoms using gunicorn and apache.

Creating a user
===============

For security reasons we'll create a new user with sudo rights, that we'll call ``astavomer``.

.. code-block:: console

  # adduser astavomer
  # gpasswd -a astavomer sudo

Install required packages
=========================

.. code-block:: console

  # apt-get update
  # apt-get install python python-pip apache2 git gunicorn python-ldap\
  #   build-essential libsasl2-dev python-dev libldap2-dev libssl-dev swig libvomsapi1
  # pip install flask kamaki M2Crypto


Clone the astavoms repository to a directory of your choice. In this guide we'll use ``/var/tmp/``

.. code-block:: console

  # git clone ssh://phab-vcs-user@phab.dev.grnet.gr:222/diffusion/ASTAVOMS/astavoms.git


Configuring astavoms
====================

On the same directory that you cloned astavoms there is an ``astavoms/settings.json.example`` file. Create a copy of this file named
``astavoms/settings.json`` and enter your settings.

Also you need to run

.. code-block:: console

  # python setup.py develop


Configuring gunicorn
====================

In order for gunicorn to run the ``astavoms`` application a configuration file under the directory
``/etc/gunicorn.d/``. We'll name it ``astavoms`` and it will contain::

	CONFIG = {
	 'mode': 'wsgi',
	 'working_dir': '/var/tmp/astavoms/astavoms',
	 'python': '/usr/bin/python',
	 'user': 'astavomer',
	 'group': 'www-data',
	 'args': (
	   '--bind=127.0.0.1:8000',
	   '--workers=6',
	   '--timeout=60',
	   '--log-level=DEBUG',
	   '--log-file=/var/log/astavoms/gunicorn.log',
	   'wsgi'
	 ),
	}

    This will run your flask application using gunicorn on port 8000 of 127.0.0.1. You can change the configuration according to your needs.

Configuring apache
==================

Create an apache configuration file under the directory ``/etc/apache2/sites-available`` with the name ``myapp`` that contains::

    <VirtualHost *:80>
      ServerName astavoms.live

      RewriteEngine On
      RewriteRule (.*) https://%{HTTPS_HOST}%{REQUEST_URI}
    </VirtualHost>

Create an apache configuration file under the directory ``/etc/apache2/sites-available`` with the name ``myapp-ssl`` that contains::

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

And finally link the newly created files on sites-enabled and enable some apache2 modules.

.. code-block:: console

  # ln -s /etc/apache2/sites-available/myapp /etc/apache2/sites-enabled/myapp
  # ln -s /etc/apache2/sites-available/myapp-ssl /etc/apache2/sites-enabled/myapp-ssl
  # a2enmod ssl headers rewrite proxy proxy_http
  # service apache2 restart

Creating SSL certificates
=========================

You might have noticed that we used some SSL certificate files on the previous step. In order to create a self signed certificate you need to run:

.. code-block:: console

  # openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/astavoms.key -out /etc/ssl/certs/astavoms.pem
