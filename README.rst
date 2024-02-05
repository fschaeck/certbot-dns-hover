certbot-dns-hover
=====================

Hover DNS Authenticator plugin for Certbot

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the Hover Domain Administration API
at https://www.hover.com/api

This implementation is gleaned from the implementation of certbot-dns-ispconfig
by Matthias Bilger, which can be found at https://github.com/m42e/certbot-dns-ispconfig
I used his project as a starting point for the code as well as this documentation.

Configuration of Hover
---------------------------

You have to have a user, with the rights to administrate the domain's DNS at https://www.hover.com.
This user must have two factor authentication enabled and the TOTP secret must be put into the
credentitals file (see below) for the plugin to be able to create the TOTP token for login.

Also the domain in questions needs to be configured to use the name servers of hover.com to be able to
create and delete the TXT records.

.. _Hover: https://www.hover.com/
.. _certbot: https://certbot.eff.org/

Installation
------------

::

    pip install certbot-dns-hover


Named Arguments
---------------

To start using DNS authentication for hover, pass the following arguments on
certbot's command line:

===================================================== =================================================
``--authenticator certbot-dns-hover:dns-hover``       select the authenticator plugin (Required)

``--certbot-dns-hover:dns-hover-credentials``         Hover User credentials INI file. (Required)

``--certbot-dns-hover:dns-hover-propagation-seconds`` waiting time for DNS to propagate before asking
                                                      the ACME server to verify the DNS record.
                                                      (Default: 10, Recommended: >= 600)
===================================================== =================================================

(Note that the verbose and seemingly redundant ``certbot-dns-hover:`` prefix
is currently imposed by certbot for external plugins.)


Credentials
-----------

An example ``credentials.ini`` file:

.. code-block:: ini

   certbot_dns_hover:dns_hover_hoverurl = https://www.hover.com
   certbot_dns_hover:dns_hover_username = my-hover-admin-username
   certbot_dns_hover:dns_hover_password = very-secure-hover-admin-user-password
   certbot_dns_hover:dns_hover_totpsecret = very-very-secure-2fa-totp-secret


The path to this file can be provided interactively or using the
``--certbot-dns-hover:dns-hover-credentials`` command-line argument. Certbot
records the path to this file for use during renewal, but does not store the
file's contents.

**CAUTION:** You should protect these API credentials as you would the
password to your hover account. Users who can read this file can use these
credentials to issue arbitrary API calls on your behalf. Users who can cause
Certbot to run using these credentials can complete a ``dns-01`` challenge to
acquire new certificates or revoke existing certificates for associated
domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

To acquire a single certificate for both ``example.com`` and
``*.example.com``, waiting 900 seconds for DNS propagation:

.. code-block:: bash

   certbot certonly \
     --authenticator certbot-dns-hover:dns-hover \
     --certbot-dns-hover:dns-hover-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
     --certbot-dns-hover:dns-hover-propagation-seconds 900 \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'example.com' \
     -d '*.example.com'


Docker
------

In order to create a docker container with a certbot-dns-hover installation,
create an empty directory with the following ``Dockerfile``:

.. code-block:: docker

    FROM certbot/certbot
    RUN pip install certbot-dns-hover

Proceed to build the image::

    docker build -t certbot/dns-hover .

Once that's finished, the application can be run as follows::

    docker run --rm \
       -v /var/lib/letsencrypt:/var/lib/letsencrypt \
       -v /etc/letsencrypt:/etc/letsencrypt \
       --cap-drop=all \
       certbot/dns-hover certonly \
       --authenticator certbot-dns-hover:dns-hover \
       --certbot-dns-hover:dns-hover-propagation-seconds 900 \
       --certbot-dns-hover:dns-hover-credentials \
           /etc/letsencrypt/.secrets/domain.tld.ini \
       --no-self-upgrade \
       --keep-until-expiring --non-interactive --expand \
       --server https://acme-v02.api.letsencrypt.org/directory \
       -d example.com -d '*.example.com'

It is suggested to secure the folder as follows:

.. code-block:: bash

	chown root:root /etc/letsencrypt/.secrets
	chmod 600 /etc/letsencrypt/.secrets


