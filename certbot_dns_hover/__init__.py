"""
The `~certbot_dns_hover.dns_hover` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Hover REST API.
Named Arguments
---------------
========================================  =====================================
``--dns-hover-credentials``               Hover Domain Administration credentials
                                          INI file. (Required)
``--dns-hover-propagation-seconds``       The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 120)
========================================  =====================================
Credentials
-----------
Use of this plugin requires a configuration file containing Hover Domain
Administration credentials, obtained from your DNSimple
`System > Remote Users`.
.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:
   # Hover Domain Adminstration credentials used by Certbot
   dns_hover_hoverurl = https://www.hover.com
   dns_hover_username = myispremoteuser
   dns_hover_password = mysecretpassword
   dns_hover_totpsecret = ultrasecuretotpsecret

The path to this file can be provided interactively or using the
``--dns-hover-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.
.. caution::
   You should protect these API credentials as you would a password. Users who
   can read this file can use these credentials to issue arbitrary API calls on
   your behalf. Users who can cause Certbot to run using these credentials can
   complete a ``dns-01`` challenge to acquire new certificates or revoke
   existing certificates for associated domains, even if those domains aren't
   being managed by this server.
Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).
Examples
--------
.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``
   certbot certonly \\
     --dns-hover \\
     --dns-hover-credentials ~/.secrets/certbot/hover.ini \\
     -d example.com
.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``
   certbot certonly \\
     --dns-hover \\
     --dns-hover-credentials ~/.secrets/certbot/hover.ini \\
     -d example.com \\
     -d www.example.com
.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 240 seconds
             for DNS propagation
   certbot certonly \\
     --dns-hover \\
     --dns-hover-credentials ~/.secrets/certbot/hover.ini \\
     --dns-hover-propagation-seconds 240 \\
     -d example.com
"""
