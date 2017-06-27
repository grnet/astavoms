Open ID Connect support
^^^^^^^^^^^^^^^^^^^^^^^
To support Open ID Connect (OIDC), ``astavoms`` must run behind an HTTP server
configured to act as an OIDC Relying Party for EGI CheckIn.

For more information on OIDC for EGI CheckIn, see
https://wiki.egi.eu/wiki/AAI_guide_for_SPs#Claims

Flow
====
In short, a user should be able to request credentials for a supported Synnefo
deployment (e.g., ~okeanos), and ``astavoms`` must authenticate and authorize
the user using the OIDC protocol and based on EGI CheckIn.

In detail:
- User client ----> ``astavoms`` "GET /v3/auth/OS-FEDERATION/websso/oidc"
- ``astavoms`` ----> User Client "Redirect to EGI CheckIn, with
                                  astavoms.example.com/oidc/callback as a
                                  redirect URI"
- User Client ----> EGI CheckIn "Request for authentication and authorization"
- EGI CheckIn guides User Client through various steps of Authentication and
  Authorization
- EGI CheckIn ----> User client "Redirect to astavoms.example.com/oidc/callback
                                 with a <code>"
- User Client ----> ``astavoms`` "GET /oidc/callback?code=<code>"
- ``astavoms`` uses code to extract user access tokens from EGI CheckIn, then to
access user information from EGI CheckIn services. Then, ``astavoms`` checks
internal records and maps the user to a Synnefo account.
- ``astavoms`` ----> User Client "202   {... token: ....}"

Register to EGI CheckIn
=======================
First, go to https://aai.egi.eu/oidc/ and register your client. Make sure you
register "https://astavoms.example.com/oidc/callback" as a redirect URI. A
"Client ID" and a "Client Secret" will be generated. Keep them safe, because
you will need them in a later step.

Configure Apache2 as OIDC RP
============================
First, install the auth_openidc module:
.. code-block:: console

    $ sudo apt-get install libapache2-mod-auth-openidc

Add to /etc/apache2/sites-available/astavoms-ssl.conf
.. code-block:: console

    ...
    <VirtualHost _detauk:443>
    ...
    # For OIDC
    <Location ~ "/v3/auth/OS-FEDERATION/websso/oidc">
        AuthType openid-connect
        Require valid-user
    </Location>
    ...
    </VirtualHost>
    ...

Add to /etc/apache2/mods-evailable/auth_openidc.conf
.. code-block:: console

    OIDCRedirectURI https://<astavoms URL>/oidc/callback
    OIDCCryptoPassphrase <Choose a safe passphrase>
    OIDCCookiePath /
    OIDCProviderMetadataURL https://aai.egi.eu/oidc/.well-known/openid-configuration
    OIDCResponseType "code"
    OIDCClientID <You got this from EGI CheckIn>
    OIDCClientSecret <You got this from EGI CheckIn>
    OIDCScope "openid email profile offline_access"
    OIDCRemoteUserClaim sub

Now, restart Apache:
.. code-block:: console

    $ sudo service apache2 restart

To test it, hit astavoms.example.com/v3/auth/OS-FEDERATION/websso/oidc with a browser. You must be redirected to Authentication and/or Authorization pages
outside of ``astavoms``.
    

``astavoms`` Settings
=================

Fill these to the settings.json:

.. code-block:: json

    {...
        "oidc": {
            "endpoints": {
                "token": "https://aai.egi.eu/oidc/token",
                "user_info": "https://aai.egi.eu/oidc/userinfo"
            },
            "client_id": "<You got this from EGI CheckIn>",
            "client_secret": "<You got this from EGI CheckIn>",
            "redirect_uri": "https://astavoms.example.com/oidc/callback"
        }
    ...
    }

Now, restart gunicorn:

.. code-block:: console

    $ sudo service gunicorn restart

The service must be ready for OIDC users.
