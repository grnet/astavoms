Context
=======

The purpose of our proxy service is to provide Synnefo credentials for valid VO
users to be used by other Synnefo/EGI application i.e., snf-occi and
snf-cdmi. Therefore, the service will be interfacing with three components:

* A Synnefo/EGI (i.e. snf-occi, snf-cdmi) component which receives and services
  the request

* A VOMS authentication component

* A Synnefo/Astakos authentication component


Functionality
=============

When a Synnefo/EGI service is requesting credentials for a VO user, the proxy
must:

1. Check the validity of the VO user
2. Retrieve Synnefo credentials

The key functionality of the system is that, if a VO user is valid, then they
are considered valid Synnefo users even if they don't exist as such yet.

1. Authenticate VOMS
--------------------

The service will authenticate a VO user by using the libvomsapi1 library. This
is a C++ library which is maintained by contributors affiliated to EGI and it
is the de facto method for authenticating VOMS.

Still, operations must be performed on the host machine, in order to be able to
validate VOMS. The main concern is to maintain VO certificates on the host
machine.

If the user cannot be validated, the proxy must notify the caller.

2. Maintain user LDAP
---------------------

An LDAP directory is used to keep user information. The directory is updated
in a lazy way, so that only the users who actually use the infrastructure will
ever be added.

3. Retrieve Synnefo Credentials
-------------------------------

There are four cases, based on the entries of the user directory:

VOMS user and corresponding Synnefo credentials in LDAP
'''''''''''''''''''''''''''''''''''''''''''''''''''''''

In this case, check if the Synnefo credentials are still valid (e.g., the token
may be expired). If they are not, they are updated (e.g., the token is
refreshed). Then, they are returned to the caller application.

VOMS user not in LDAP
'''''''''''''''''''''

Since the user is authenticated, create them in Synnefo and then update the LDAP.

The name and email of the user are required in order to add them in Synnefo.In
order to avoid conflicts, it suffices to create a mock email address for the user,
which is based on the users VOMS credentials.

User policies
=============

An important aspect of the proxy is to manage user policies (e.g., quotas) in a
way that makes sense from the EGI point of view. For example, if a valid VO
user is allowed to use a set of resources, the proxy must be able to subscribe
them to specific projects, approved for this purpose. In specific, each VO will
be assigned to a project.

User policies will be considered in a next stage and their implementation will
not be part of the prototype.

The API
=======

A RESTful API with a simple call will be the interface of the proxy with the
Synnefo/EGI applications.


.. rubric:: VO user to Synnefo user

========================== ====== =================
Description                Method Endpoint
========================== ====== =================
`Get Synnefo credentials`_ POST   ``/authenticate``
========================== ====== =================

|
==============  ================
Request Header  Value
==============  ================
Content-type    application/json
==============  ================

|
==============  ================
Request Data    Value
==============  ================
Content-type    application/json
==============  ================

Request data::

    {
        "dn": <User DN>,
	"cert": <User PEM certificate>,
	"chain": <PEM chain>
    }


Response data::

    {
        "snf:uuid": <Synnefo user UUID>,
        "snf:token": <Synnefo user token>,
        "snf:project": <Synnefo Project ID>,
        "mail": <user e-mail>,
        "serverca": <VOMS server CA>,
        "voname": <VO name>,
        "uri": <VO URI>,
        "server": <VO server>,
        "version": <OCCI version>,
        "user": <User description>,
        "userca": <User CA>,
        "serial": <User serial>,
        "fqans": [...],
        "not_after": <Date (see OCCI)>,
        "not_before": <Date (see OCCI)>
    }

.. note:: All response data is produced by VOMS authentication, except from
	Synnefo-related information, which is prefixed with 'snf:'
