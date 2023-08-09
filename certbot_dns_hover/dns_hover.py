"""
letsencrypt certbot DNS Authenticator for domains hosted at Hover (https://www.hover.com)

This implementation is based on the implementation of certbot-dns-ispconfig
of Matthias Bilger which can be found at https://github.com/m42e/certbot-dns-ispconfig
"""

import logging
import re
import base64
import hashlib
import hmac
import calendar
import datetime
import time

from typing import Any, Optional, Union

import zope.interface

from requests import Session
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

URL_HOVER_BASE          = 'https://www.hover.com'

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
            + "the Hover REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Hover credentials INI file",
            {
                "hoverurl": "Base-URL of Hover DNS API",
                "username": "Username for Hover Domain Administration.",
                "password": "Password for Hover Domain Administration.",
                "totpsecret": "Secret for 2FA Time-based OTP Generator.",
            },
        )
        self.hover_client = _HoverClient(
                                self.credentials.conf("hoverurl"),
                                self.credentials.conf("username"),
                                self.credentials.conf("password"),
                                self.credentials.conf("totpsecret"),
                            )

    def _perform(self, domain, validation_name, validation):
        self.challenge_count += 1
        self.hover_client.add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self.hover_client.del_txt_record(domain, validation_name, validation)
        self.challenge_count -= 1
        if self.challenge_count<=0:
            self.hover_client.logout()


class _HoverClient(object):
    """
    Encapsulates all communication with the Hover Domain Administration REST API.
    """

    def __init__(self, hoverBaseUrl, username, password, totpsecret):
        logger.info("creating HoverClient")
        self.hoverBaseUrl = hoverBaseUrl
        self.username = username
        self.password = password
        self.totpsecret = totpsecret
        self.session = Session()
        self.loggedIn = False

    def _get_url(self, action):
        return "{0}/{1}".format(self.hoverBaseUrl,re.sub('^/+','',action))

    def _login(self):
        if self.loggedIn:
            return
        logger.info('logging in as {0}'.format(self.username))
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0'
        self.session.headers['Accept'] = '*/*'
        self.session.headers['Accept-Language'] = 'en-US,en;q=0.5'
        self.session.headers['Referer'] = self.hoverBaseUrl

        try:
            result = self._request('GET','signin',json=False) // initializing cookie hoversession
        except Exception as ex:
            logger.error('Failed to get URL {0}: {1}'.format(self._get_url('signin'), ex))
            self.loggedIn = False
            raise

        self.session.headers['Referer'] = self._get_url("signin")
        try:
            # logging in phase 1
            result = self._request('POST','signin',json={'username':self.username, 'password':self.password, 'token': None })
        except Exception as ex:
            logger.error('Failed to log in as {0}: {1}'.format(self.username, ex))
            self.loggedIn = False
            raise

        if result.get("status", "")!="need_2fa":
            logger.error("Status 'need_2fa' expected but got {0}.".format(result.get("status")))
            self.loggedIn = False
            raise ValueError("Status 'need_2fa' expected but got {0}.".format(result.get("status"))))

        try:
            totp = TOTP(self.totpsecret)
            result = self._request('POST','signin/auth2.json',json={'code': totp.now()})
        except Exception as ex:
            logger.error('Failed to log in as {0}: {1}'.format(self.username, ex))
            self.loggedIn = False
            raise

        logger.info('successfully logged in as {0}'.format(self.username))
        self.loggedIn = True

    def logout(self):
        '''
        If an active session exists, it does a logout from the API
        and closes the session. Any exceptions are willfully ignored.
        '''
        logger.info('closing Hover client')
        if self.loggedIn:
            try:
                url = self._get_url_logout()
                logger.info('logging out via {0}'.format(url))
                self.session.get(url)
            except Exception as err:
                logger.info('failed to logout: {0}'.format(err))
            else:
                logger.info('successfully logged out')
            finally:
                self.loggedIn = False
                
    def _request(self, requestType, actionUrl, **kwargs):
        url = self._get_url(actionUrl)
        logger.debug("    request to URL: %s", url)
        resp = self.session.request(requestType,url,**kwargs)
        if resp.status_code != 200:
            if resp.text!=None and len(resp.text)>0:
                raise errors.PluginError("HTTP Error {0}: {1}".format(resp.status_code,resp.text))
            else:
                raise errors.PluginError("HTTP Error {0}".format(resp.status_code))
        logger.debug('      returned 200')
        try:
            result = resp.json()
        except:
            raise errors.PluginError("API response with non JSON: {0}".format(resp.text))
        
        if result.get("succeeded",False)==True:
            logger.debug('      -> API request succeeded')
            return result
        else:
            raise errors.PluginError("API request unsuccessful: {0}".format(resp.text))

    def _get_txt_record(self, domain, record_name, record_content):
        logger.debug('  looking for txt record {0} from domain {1} with content {2}'.format(record_name,domain,record_content))
        domainDnsList = self._api_request('GET', 'domains/{0}/dns'.format(domain))
        logger.debug('    received dns list {0}'.format(domainDnsList))
        for domainDns in domainDnsList.get('domains'):
            if domainDns.get('domain_name')==domain:
                for rec in domainDns.get('entries'):
                    if (rec.get('type')== 'TXT'
                        and rec.get('name')+'.'+domain==record_name
                        and rec.get('content')==record_content):
                        
                        logger.debug('    -> txt record found: {0}'.format(rec))
                        return rec
        logger.info('    -> txt record not found.')
        return None

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Hover API
                            
        """
        self._login()
        logger.info("ensuring txt record {0} at {1} with content {2} exists.".format(record_name,domain,record_content))
        record = self._get_txt_record(domain,record_name,record_content)
        if record is None:
            logger.info('  inserting new txt record')
            self._api_request('POST','/domains/{0}/dns'.format(domain),
                              json={'content':    record_content,
                                    'name':       record_name,
                                    'type':       'TXT'
                                    })
            record = self._get_txt_record(domain, record_name,record_content)
            if record is None:
                raise errors.PluginError("  -> something went wrong with the insert, even though there was no error reported.")
            else:
                logger.info('  -> successfully inserted new txt record')
        else:
            recId = record.get('id')
            logger.info("  -> txt record exists already under id {0}".format(recId))
            
    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Hover API
        """
        self._login()
        logger.info("ensuring txt record {0} at {1} with content {2} is deleted".format(record_name,domain,record_content))
        record = self._get_txt_record(domain, record_name, record_content)
        if record is None:
            logger.info("  -> txt record does not exist")
        else:
            recId= record.get('id')
            logger.info("  deleting existing txt record under id {0}".format(recId))
            self._api_request('DELETE','/dns/{0}'.format(recId))
            logger.info('  -> successfully deleted txt record')


class TOTP(Object):
    """
    Handler for time-based OTP counters.
    """

    def __init__(
        self,
        s: str,
        digits: int = 6,
        digest: Any = hashlib.sha1,
        name: Optional[str] = None,
        issuer: Optional[str] = None,
        interval: int = 30,
    ) -> None:
        """
        :param s: secret in base32 format
        :param interval: the time interval in seconds for OTP. This defaults to 30.
        :param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        """

        self.interval = interval
        self.digits = digits
        if digits > 10:
            raise ValueError("digits must be no greater than 10")
        self.digest = digest
        self.secret = s
        self.name = name or "Secret"
        self.issuer = issuer


    def generate_otp(self, input: int) -> str:
        """
        :param input: the HMAC counter value to use as the OTP input.
            Usually either the counter, or the computed integer based on the Unix timestamp
        """
        if input < 0:
            raise ValueError("input must be positive integer")
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        str_code = str(10_000_000_000 + (code % 10**self.digits))
        return str_code[-self.digits :]


    def byte_secret(self) -> bytes:
        secret = self.secret
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)
        return base64.b32decode(secret, casefold=True)


    @staticmethod
    def int_to_bytestring(i: int, padding: int = 8) -> bytes:
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(bytearray(reversed(result)).rjust(padding, b"\0"))



    def now(self) -> str:
        """
        Generate the current time OTP

        :returns: OTP value
        """
        return self.generate_otp(self.timecode(datetime.datetime.now()))


    def timecode(self, for_time: datetime.datetime) -> int:
        """
        Accepts either a timezone naive (`for_time.tzinfo is None`) or
        a timezone aware datetime as argument and returns the
        corresponding counter value (timecode).

        """
        if for_time.tzinfo:
            return int(calendar.timegm(for_time.utctimetuple()) / self.interval)
        else:
            return int(time.mktime(for_time.timetuple()) / self.interval)


