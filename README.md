Astakos VOMS Proxy Server and Tools
===================================

`astavoms` is a minimal proxy server able to translate VOMS user information to
Synnefo/Astakos credentials.

Install and deploy
------------------

TODO
apt-get install build-essential libsasl2-dev python-dev libldap2-dev libssl-dev swig libvomsapi1

Using the server
----------------

The proxy server is given VOMS user information and returns Synnefo/Astakos
credentials, e.g.:

```
> POST https://astavoms.host:5000/voms2snf
>   X-Auth-Token: Trusted-client-token
>   Content-Type: application/json
>
> {"cn": "/C=org/O=example/CN=Tyler Durden", "vo": "example"}

< 202 ACCEPTED
< 
< {
<    "uuid": "the-synnefo-astakos-user-uuid",
<    "token": "the-synnefo-astakos-user-token"
< }
```

Tools
-----

A kamaki extension for the OCCI/VOMS - Astakos API (
http://docs.astakostest.apiary.io/ ) for user creation and token refreshment

An LDAP driver for accessing and updating an Astakos-VOMS aware LDAP directory

TODO: a tool for (manually) updating VOs and, maybe, VO users
