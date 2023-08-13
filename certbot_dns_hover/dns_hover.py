"""
letsencrypt certbot DNS Authenticator for domains hosted at Hover (https://www.hover.com)

This implementation is based on the implementation of certbot-dns-ispconfig
of Matthias Bilger which can be found at https://github.com/m42e/certbot-dns-ispconfig
"""

import logging
from typing import Any, Optional, Union
from .HoverClient import HoverClient, HoverClientException

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

__VERSION__ = "1.2.0"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Hover

    This Authenticator uses the Hover REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Hover for DNS)."

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.hover_client = None
        self.challenge_count = 0

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="Hover credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the Hover (www.hover.com) REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Hover credentials INI file",
            {
                "hoverurl": "URL of Hover Server (https://www.hover.com)",
                "username": "Username for Hover Domain Administration.",
                "password": "Password for Hover Domain Administration.",
                "totpsecret": "Secret for 2FA Time-based OTP Generator.",
            },
        )
        try:
            self.hover_client = HoverClient(
                                    self.credentials.conf("hoverurl"),
                                    self.credentials.conf("username"),
                                    self.credentials.conf("password"),
                                    self.credentials.conf("totpsecret"),
                                    logger=logger
                                )
        except BaseException as ex:
            raise errors.PluginError(str(ex)) from ex

    def _perform(self, domain, validation_name, validation):
        self.challenge_count += 1
        try:
            self.hover_client.add_record(domain, 'TXT', validation_name, validation)
        except BaseException as ex:
            raise errors.PluginError("Adding TXT record for ACME challenge failed: {0}".format(str(ex))) from ex

    def _cleanup(self, domain, validation_name, validation):
        try:
            self.hover_client.delete_record(domain, 'TXT', validation_name, validation)
        except BaseException as ex:
            logger.warning("Deleting TXT record from ACME challege failed: {0}".format(str(ex)))

        self.challenge_count -= 1
        if self.challenge_count<=0:
            try:
                self.hover_client.logout()
            except BaseException as ex:
                logger.warning("Logging out of {0} failed: {1}".format(self.credentials.conf("hoverurl"), str(ex)))


