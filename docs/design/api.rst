Context
=======

The purpose of our proxy service is to provide Synnefo credentials for valid VO
users to be used by other Synnefo/EGI application i.e., snf-occi and
snf-cdmi. Therefore, the service will be interfacing with three components:

* A Synnefo/EGI service which to initiate the request

* A VO authentication service to validate the VO credentials

* A Synnefo/Astakos service to provide the Synnefo credentials

In the present document we focus on the first interface.

Functionality
=============

When a Synnefo/EGI service is requesting credentials for a VO user, the proxy
must:

1. Check the validity of the VO user
2. Retrieve Synnefo credentials

The key functionality of the system is that, if a VO user is valid, then they
are considered valid Synnefo users even if they don't exist as such yet.

1. Check the validity of the VO user
------------------------------------

The service will authenticate a VO user by calling an external VO
authentication service.

If the user cannot be validated, the proxy must notify the caller.

2. Retrieve Synnefo Credentials
-------------------------------

There are four cases, based on the entries of the user directory:

VO user and corresponding Synnefo credentials exist
'''''''''''''''''''''''''''''''''''''''''''''''''''

In this case, check if the Synnefo credentials are still valid (e.g., the token
may be expired). If they are not, they are updated (e.g., the token is
refreshed). Then, they are returned to the caller application.

VO user exists but no Synnefo credentials
'''''''''''''''''''''''''''''''''''''''''

In this case, create a new user. The name and email of the user must be
created in a way that no conflicts will emerge. In this stage, it suffices to
create a mock email address for the user, which is based on the users VO
credentials.

VO or VO user does not exist
''''''''''''''''''''''''''''

Since they are valid VO users, they are created in the proxy directory. Then,
the above procedure is followed.

User policies
=============

An important aspect of the proxy is to manage user policies (e.g., quotas) in a
way that makes sense from the EGI point of view. For example, if a valid VO
user is allowed use a set of resources, the proxy must be able to subscribe
them to specific projects, approved for this purpose. The specifics of the
the policies are out of the scope of this document.

User policies will be considered in a next stage and their implementation will
not be involved in the prototype.

The API
=======

A RESTful API with a simple call will be the interface of the proxy with the
Synnefo/EGI applications.


.. rubric:: VO user to Synnefo user

========================== ====== =============
Description                Method Endpoint
========================== ====== =============
`Get Synnefo credentials`_ POST   ``/voms2snf``
========================== ====== =============

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
		"cn": <VO user certified name>,
		"vo": <Virtual Organization>
	}


Response data::

	{
		"uuid": <Synnefo user uuid>,
		"token": <Synnefo user token>,
		"project": <Project ID to be used for resource allocation>
	}
