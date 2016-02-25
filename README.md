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

TODO: Setting up the system for VOMS authentication


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
http://docs.astakostest.apiary.io/ ) for user creation and token refreshment

An LDAP driver for accessing and updating an Astakos-VOMS aware LDAP directory

TODO: a tool for (manually) updating VOs and, maybe, VO users
