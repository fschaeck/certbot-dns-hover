"""
This module provides the class HoverClient that encapsulates the
DNS admin API at https://www.hover.com
"""

import logging
import base64
import hashlib
import hmac
import calendar
import datetime
import time

from requests import Session

__VERSION__ = "1.2.0"

class HoverClientException(Exception):
    pass

class HoverClient(object):
    """
    Encapsulates all communication with the Hover Domain Administration REST API.
    """

    def __init__(self, hover_base_url, username, password, totpsecret, logger=None):
        if logger is None:
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        self.logger.info("Creating HoverClient v{0}".format(__VERSION__))
        self.hover_base_url = hover_base_url
        self.username = username
        self.password = password
        self.totpsecret = totpsecret
        self.session = Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            })
        self.loggedIn = False

    def _get_url(self, action):
        return "{0}/{1}".format(self.hover_base_url,action.lstrip('/'))

    def _login(self):
        if self.loggedIn:
            try:
                # check if the login is still valid
                self.session.get(self._get_url('api/domains'))
                return
            except:
                # if there was a problem - redo the login
                self.loggedIn = False

        self.logger.info('Logging in as {0}'.format(self.username))
        self.session.cookies.clear();
        self.session.headers['Referer'] = self.hover_base_url

        # Login start: initializing cookie hover_session
        url = self._get_url('signin')
        try:
            self.session.get(url)
        except Exception as ex:
            msg = 'Failed to get URL {0}: {1}'.format(url, ex)
            self.logger.error(msg)
            raise HoverClientException(msg) from ex

        if self.session.cookies.get('hover_session') is None:
            msg = "Failed to initialize login session. No cookie 'hover_session' found."
            self.logger.error(msg)
            raise HoverClientException(msg)

        # Login phase 1: username and password
        self.session.headers['Referer'] = url 
        try:
            result = self._request('POST','signin/auth.json',
                                   json={'username':self.username,
                                         'password':self.password,
                                         'token': None })
        except Exception as ex:
            msg = 'Failed to log in as {0}: {1}'.format(self.username, ex)
            self.logger.error(msg)
            raise HoverClientException(msg) from ex

        if result.get("status", "")!="need_2fa":
            msg = "Status 'need_2fa' expected but got {0}.".format(result.get("status"))
            self.logger.error(msg)
            self.loggedIn = False
            raise HoverClientException(msg)

        # Login phase 2: Timebased OTP Token
        try:
            result = self._request('POST','signin/auth2.json',json={'code': self._get_totp_token()})
        except Exception as ex:
            msg = 'Failed to log in as {0}: {1}'.format(self.username, ex)
            self.logger.error(msg)
            self.loggedIn = False
            raise HoverClientException(msg) from ex

        self.logger.info('successfully logged in as {0}'.format(self.username))
        self.session.headers['Referer'] = self._get_url("control_panel")
        self.loggedIn = True


    def logout(self):
        '''
        If an active session exists, it does a logout from the API
        and closes the session. Any exceptions are willfully ignored.
        '''
        self.logger.info('Closing Hover Client session')
        if self.loggedIn:
            try:
                url = self._get_url('logout')
                self.logger.info('logging out via {0}'.format(url))
                self.session.get(url)
            except Exception as err:
                self.logger.warning('failed to logout: {0}'.format(err))
            else:
                self.logger.info('successfully logged out')
            finally:
                self.loggedIn = False


    def _request(self, requestType, actionUrl, **kwargs):
        url = self._get_url(actionUrl)
        self.logger.debug("    request to URL: %s", url)
        resp = self.session.request(requestType,url,**kwargs)
        if resp.status_code != 200:
            if resp.text!=None and len(resp.text)>0:
                raise HoverClientException("API request {2} failed with HTTP error {0}: {1}"
                                           .format(resp.status_code,resp.text, url))
            else:
                raise HoverClientException("API request {1} failed with HTTP error {0}"
                                           .format(resp.status_code, url))
        self.logger.debug('      returned 200')
        try:
            result = resp.json()
        except:
            raise HoverClientException("API request {1} responded with non JSON data: {0}".format(resp.text, url))
        
        if result.get("succeeded",False)==True:
            self.logger.debug('      -> API request succeeded')
            return result
        else:
            raise HoverClientException("API request {1} unsuccessful: {0}".format(resp.text, url))

    def _get_records(self, domain, record_type, record_name, record_content=None):
        self.logger.debug('  looking for {0} records {1} from domain {2}{3}'
                          .format(record_type, record_name, domain,
                                  ' with content {0}'.format(record_content) if record_content!=None else ''))
        try:
            domainDnsList = self._request('GET', 'api/domains/{0}/dns'.format(domain))
        except Exception as ex:
            msg = ("Failed to get DNS '{0}' record {1} from domain {2}: {3}"
                   .format(record_type, record_name, domain, ex))
            self.logger.error(msg)
            raise HoverClientException(msg) from ex

        self.logger.debug('    received dns list {0}'.format(domainDnsList))
        result = []
        for domainDns in domainDnsList.get('domains',{}):
            if domainDns.get('domain_name','')==domain:
                for rec in domainDns.get('entries',{}):
                    if (rec.get('type')== record_type
                        and rec.get('name')+'.'+domain==record_name
                        and (record_content is None or rec.get('content')==record_content)):
                        self.logger.debug('    -> record found: {0}'.format(rec))
                        result.append(rec)
        self.logger.debug('    record not found.')
        return result

    def add_record(self, domain, record_type, record_name, record_content, ttl=900):
        """
        Add a DNS record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_type: The record type. One of MX, TXT, CNAME, A, AAAA
        :param str record_name: The record name.
        :param str record_content: The record content.
        :param str record_ttl: TTL in seconds of record if newly created. Default is 900.
        :raises HoverClient.HoverClientException: if an error occurs communicating with the Hover API
                            
        """
        self.login()
        self.logger.info("Ensuring {0} record {1} at {2} with content {3} exists."
                         .format(record_type, record_name, domain, record_content))
        records = self._get_records(domain, record_type, record_name, record_content)
        if records is None:
            msg = "Domain {0} does not exist.".format(domain)
            self.logger.error(msg)
            raise HoverClientException(msg)
        elif len(records)==0:
            self.logger.debug('  inserting new record')
            self._request('POST','api/domains/{0}/dns'.format(domain),
                          json={'content':    record_content,
                                'name':       record_name,
                                'type':       record_type,
                                'ttl':        record_ttl,
                               })
            records = self._get_records(domain, record_type, record_name, record_content)
            if len(records)==0:
                raise HoverClientException("Something went wrong when adding {0} record {1} for domain {2} even though there was no error reported.".format(record_type, record_name, domain))
            else:
                self.logger.debug('  -> successfully inserted new record')
        else:
            recId = records[0].get('id')
            self.logger.debug("  -> {0} record {1} exists already under id {2}"
                              .format(record_type, record_name, recId))


    def delete_record(self, domain, record_type, record_name, record_content=None):
        """
        Delete a record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_type: The record type to delete.
        :param str record_name: The record name to delete.
        :param str record_content: The record content of the record to delete.
        :raises HoverClient.HoverClientException: if an error occurs communicating with the Hover API
        """
        self.login()
        self.logger.info("Ensuring {0} record {1} of domain {2} with content {3} is deleted"
                         .format(record_type, record_name, domain,
                                 record_content if record_content is not None else '<any>'))
        records = self._get_records(domain, record_type, record_name, record_content)
        if records is None:
            msg = "Domain {0} does not exist.".format(domain)
            self.logger.error(msg)
            raise HoverClientException(msg)
        elif len(records)==0:
            self.logger.debug("  -> {0} record {1} does not exist".format(record_type, record_name))
        else:
            for record in records:
                recId= record.get('id')
                self.logger.debug("  Deleting existing record under id {0}".format(recId))
                self._request('DELETE','api/dns/{0}'.format(recId))
            self.logger.debug('  -> successfully deleted all TXT records in question.')

    def update_record(self, domain, record_type, record_name, record_content, old_record_content=None):
        """
        Update a record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_type: The record type to update.
        :param str record_name: The record name to update.
        :param str record_content: The new record content of the record to update.
        :param str old_record_content: The old record content of the record to update.
        :raises HoverClient.HoverClientException: if an error occurs communicating with the Hover API
        """
        self.login()
        self.logger.info("Updating {0} record {1} of domain {2}{3}."
                         .format(record_type, record_name, domain,
                                 'with content '+record_content if record_content is not None else ''))
        records = self._get_records(domain, record_type, record_name, old_record_content)
        if records is None:
            msg = "Domain {0} does not exist.".format(domain)
            self.logger.error(msg)
            raise HoverClientException(msg)
        elif len(records)==0:
            msg = ("Requested {0} record {1} for domain {2}{3} does not exist."
                   .format(record_type, record_name, domain,
                           'with content '+old_record_content if old_record_content is not None else ''))
            self.logger.error(msg)
            raise HoverClientException(msg)
        elif len(records)>0 and old_record_content is None:
            msg = ("Requested {0} record {1} for domain {2} exists multiple times but no current content was given."
                   .format(record_type, record_name, domain,
                           'with content '+old_record_content if old_record_content is not None else ''))
            self.logger.error(msg)
            raise HoverClientException(msg)
        else:
            for record in records:
                recId= record.get('id')
                self.logger.debug("  Updating existing record under id {0}".format(recId))
                self._request('PUT','api/dns/{0}'.format(recId),
                              json={'content':    record_content,
                                    'ttl':        record_ttl,
                                   })
            self.logger.debug('  -> successfully updated all {0} records in question.'.format(record_type))


    def _get_totp_token(self):
        """
        Get the current time-based OTP token for secret in self.totpsecret.
        """

        digits = 6
        counter = int(time.mktime(datetime.datetime.now().timetuple()) / 30)

        secret = self.totpsecret
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)
        secret = base64.b32decode(secret, casefold=True)

        hasher = hmac.new(secret, self.int_to_bytestring(counter), hashlib.sha1)
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        str_code = str(10_000_000_000 + (code % 10**digits))
        return str_code[-digits :]


    @staticmethod
    def int_to_bytestring(i, padding=8):
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


if __name__ == '__main__':
    client = HoverClient('https://www.hover.com', os.getenv('HOVER_USER_NAME','xxx'),os.getenv('HOVER_USER_PASSWORD', 'xxx'), os.getenv('HOVER_USER_TOTPSECRET','xxx'))
    client.add_record('schaeckermann.net', 'TXT', 'hugo', 'emil')
    client.del_record('schaeckermann.net', 'TXT', 'hugo', 'emil')
    client.logout()
