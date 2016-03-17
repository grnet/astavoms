Astakos VOMS Proxy Server and Tools
===================================

`astavoms` is a minimal proxy server able to translate VOMS user information to
Synnefo/Astakos credentials.

Install and deploy
------------------

Assuming a debian-like system, the following packages are required:

```
// For python-ldap
# apt-get install build-essential libsasl2-dev python-dev libldap2-dev libssl-dev

// For M2Crypto
# apt-get install swig

// For voms_helper
# apt-get install libvomsapi1
```

There are two modes of deployment: for testing/development and full scale.

The first deploys a lightweight Flask server, but it does not support any
advanced features like SSL or load balancing. It is easy to run:

```
# astavoms-server --config /etc/astavoms/settings.json start
```

The full scale method requires gunicorn and apache2 and is described in detail
in deploy.rst, along with all settings required to setup the server for VO
authentication and how to set various service settings.

Using the server
----------------

The proxy server is given VOMS user information and returns Synnefo/Astakos
credentials, e.g.:

```
> POST https://astavoms.host:5000/authenticate
>   X-Auth-Token: Trusted-client-token
>   Content-Type: application/json
>
> {"dn": ..., "cert": ..., "chain": ...}

< 202 ACCEPTED
< 
< {
<	"snf:uuid": ..., "snf:token": ..., "snf:project": ...,
<	"mail": ..., "serverca": ..., "voname": ...,
<	"uri": ..., "server": ..., "version": ...,
<	"user": ..., "userca": ..., "serial": ...,
<	"fqans": [...], "not_after": ..., "not_before": ...
< }
```

Tools
-----

A kamaki extension for the OCCI/VOMS - Astakos API (
http://docs.astakostest.apiary.io/ ) for user creation and token refreshment (astavoms.identity)

An LDAP driver for accessing and updating an LDAP directory (astavoms.ldapuser)

A kamaki extension for dealing with an astavoms service (astavomaki)

TODO: a tool for (manually) updating VOs and, maybe, VO users

## Copyright and license

Copyright (C) 2016 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
