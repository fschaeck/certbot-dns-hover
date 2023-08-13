"""
This module provides the class HoverClient that encapsulates the
DNS admin API at https://www.hover.com
"""

import os
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
    def __init__(self, hover_client, msg, *args):
        self.msg = msg % args
        super().__init__(self.msg)
        hover_client.logger.error(self.msg)
        hover_client.logout()

class HoverClient(object):
    """
    Encapsulates all communication with the Hover Domain Administration REST API.
    """

    def __init__(self, hover_base_url, username, password, totpsecret, logger=None):
        try:
            if logger is None:
                logging.basicConfig(level=logging.DEBUG)
                self.logger = logging.getLogger(__name__)
            else:
                self.logger = logger

            self.logger.info("Creating HoverClient v%s", __VERSION__)
            self.hover_base_url = hover_base_url
            self.username = username
            self.password = password
            self.totpsecret = totpsecret
            self.session = Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': self.hover_base_url
                })
            self.loggedIn = None
            self._login()
            result = self._request('GET','api/domains','retrieve domain names')
            self.domains = {}
            for domain in result.get('domains',{}):
                self.domains[domain['domain_name']] = domain
        except BaseException as ex:
            raise HoverClientException(self, "%s -> Failed to initialize HoverClient.", str(ex)) from ex

    def _get_url(self, action):
        return "{0}/{1}".format(self.hover_base_url,action.lstrip('/'))

    def _login(self):
        try:
            if self.loggedIn is not None:
                if time.monotonic()-self.loggedIn<60.0: # only double-check every minute
                    return
                try:
                    # check if the login is still valid
                    self.session.get(self._get_url('api/domains'))
                    self.loggedIn = time.monotonic()
                    return
                except:
                    # if there was a problem - redo the login
                    self.loggedIn = None

            self.logger.info('Logging in as %s', self.username)
            self.session.cookies.clear();
            self.session.cookies.set('hover_device_id','fcaf98428da8d4affebd')
            self.session.headers['Referer'] = self.hover_base_url

            # Login start: initializing cookie hover_session
            url = self._get_url('signin')
            try:
                self.session.get(url)
            except BaseException as ex:
                raise HoverClientException(self, '%s -> Failed to get URL %s.', str(ex), url) from ex

            if self.session.cookies.get('hover_session') is None:
                raise HoverClientException(self, "Failed to initialize login session. No cookie 'hover_session' found.")

            # Login phase 1: username and password
            self.session.headers['Referer'] = url 
            result = self._request('POST','signin/auth.json','login with user name and password',
                                   json={'username':self.username,
                                         'password':self.password,
                                         'token': None })

            if result.get("status", "")!="need_2fa":
                raise HoverClientException(self, "Status 'need_2fa' expected but got %s.",result.get("status"))

            # Login phase 2: Timebased OTP Token
            result = self._request('POST','signin/auth2.json','authenticate with TOTP token',
                                   json={'code': self._get_totp_token()})

            self.logger.info('Successfully logged in as %s.', self.username)
            self.session.headers['Referer'] = self._get_url("control_panel")
            self.loggedIn = time.monotonic() 
        except BaseException as ex:
            raise HoverClientException(self, '%s -> Failed to log in as %s.', str(ex), self.username) from ex


    def logout(self):
        '''
        If an active session exists, it does a logout from the API
        and closes the session. Any exceptions are willfully ignored.
        '''
        if self.loggedIn is not None:
            try:
                self.logger.info('Closing Hover Client session')
                url = self._get_url('logout')
                self.logger.info('  Logging out via %s', url)
                response = self.session.get(url, allow_redirects=False)
                if response.status_code<400:
                    self.logger.info('  Successfully logged out')
                else:
                    self.logger.warning("  Logged out with HTTP status code %d", response.status)
            except BaseException as ex:
                self.logger.warning('  Failed to logout: %s', ex)
            finally:
                self.loggedIn = None


    def _request(self, request_type, action_url, action_description, **kwargs):
        try:
            url = self._get_url(action_url)
            self.logger.debug("    %s request to URL %s to %s", request_type, url, action_description)
            resp = self.session.request(request_type,url,**kwargs)
            if resp.status_code != 200:
                if resp.text!=None and len(resp.text)>0:
                    raise HoverClientException(self, "%s request to URL %s failed with HTTP error %d: %s",
                                               request_type, url, resp.status_code, resp.text)
                else:
                    raise HoverClientException(self, "%s request to URL %s failed with HTTP error %d",
                                               request_type, url, resp.status_code)
            self.logger.debug('      returned 200')
            try:
                result = resp.json()
            except:
                raise HoverClientException(self, "%s request to URL %s responded with non JSON data: %s",
                                           request_type, url, resp.text)

            if result.get("succeeded",False)==True or result.get("status","")=="need_2fa":
                self.logger.debug('      -> request succeeded:\n%s', resp.text)
                return result
            else:
                raise HoverClientException(self, "%s request to URL %s was unsuccessful: %s", request_type, url, resp.text)
        except BaseException as ex:
            raise HoverClientException(self, "%s -> Failed to %s.", str(ex), action_description) from ex;


    def get_records(self, domain, record_type, record_name, record_content=None):
        try:
            self.logger.debug('  looking for %s records %s from domain %s%s',
                              record_type, record_name, domain,
                              ' with content {0}'.format(record_content) if record_content is not None else '')
            if not domain in self.domains:
                raise HoverClientException(self, "Domain %s does not exist.", domain)

            self._login()
            domain_dns_list = self._request('GET', 'api/domains/{0}/dns'.format(domain), 'retrieve DNS records')

            if record_name.endswith("."+domain):
                record_name = record_name[:-len(domain)-1]

            result = None
            for domain_dns in domain_dns_list.get('domains',{}):
                if domain_dns.get('domain_name','')==domain:
                    if result is None:
                        result = []
                    for rec in domain_dns.get('entries',{}):
                        if (rec.get('type')== record_type
                            and rec.get('name')==record_name
                            and (record_content is None or rec.get('content')==record_content)):
                            self.logger.debug('    -> record found: %s', str(rec))
                            result.append(rec)
            self.logger.debug('    total records found: %d', len(result))
            return result
        except BaseException as ex:
            raise HoverClientException(self, '%s -> Failed to retrieve %s records %s from domain %s%s.',
                                       str(ex), record_type, record_name, domain,
                                       ' with content {0}'.format(record_content) if record_content is not None else '',
                                      ) from ex


    def add_record(self, domain, record_type, record_name, record_content, record_ttl=900):
        """
        Add a DNS record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_type: The record type. One of MX, TXT, CNAME, A, AAAA
        :param str record_name: The record name.
        :param str record_content: The record content.
        :param str record_ttl: TTL in seconds of record if newly created. Default is 900.
        :raises HoverClient.HoverClientException: if an error occurs communicating with the Hover API

        """
        try:
            self.logger.info("Ensuring %s record %s for domain %s with content %s exists.",
                             record_type, record_name, domain, record_content)
            records = self.get_records(domain, record_type, record_name, record_content)
            if len(records)==0:
                self.logger.debug('  inserting new record')
                self._request('POST','api/domains/{0}/dns'.format(domain),
                              'insert new DNS record',
                              json={'content':    record_content,
                                    'name':       record_name,
                                    'type':       record_type,
                                    'ttl':        record_ttl,
                                   })
                records = self.get_records(domain, record_type, record_name, record_content)
                if len(records)==0:
                    raise HoverClientException(self, "Something went wrong when adding %s record %s for domain %s even though there was no error reported.",
                                               record_type, record_name, domain)
                else:
                    self.logger.debug('  -> successfully inserted new record')
            else:
                self.logger.debug("  -> record exists already under id %s", records[0].get('id'))
        except BaseException as ex:
            raise HoverClientException(self, "%s -> Failed to ensure %s record %s for domain %s with content %s exists.",
                                       str(ex), record_type, record_name, domain, record_content) from ex

    def delete_record(self, domain, record_type, record_name, record_content=None):
        """
        Delete a record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_type: The record type to delete.
        :param str record_name: The record name to delete.
        :param str record_content: The record content of the record to delete.
        :raises HoverClient.HoverClientException: if an error occurs communicating with the Hover API
        """
        try:
            self.logger.info("Ensuring all %s records %s of domain %s%s are deleted",
                             record_type, record_name, domain,
                             " with content "+record_content if record_content is not None else '')
            records = self.get_records(domain, record_type, record_name, record_content)
            if len(records)==0:
                self.logger.debug("  -> record does not exist.")
            else:
                for record in records:
                    recId= record.get('id')
                    self.logger.debug("  Deleting existing record under id %s", recId)
                    self._request('DELETE','api/dns/{0}'.format(recId), 'delete DNS record')
                self.logger.debug('  -> successfully deleted %d records.', len(records))
        except BaseException as ex:
            raise HoverClientException(self, "%s -> Failed to ensure all %s records %s of domain %s%s are deleted",
                                       str(ex), record_type, record_name, domain,
                                       " with content "+record_content if record_content is not None else '') from ex

    def update_record(self, domain, record_type, record_name,
                            record_content, record_ttl=None, old_record_content=None):
        """
        Update a record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_type: The record type to update.
        :param str record_name: The record name to update.
        :param str record_content: The new record content of the record to update.
        :param str old_record_content: The old record content of the record to update.
        :raises HoverClient.HoverClientException: if an error occurs communicating with the Hover API
        """
        try:
            self.logger.info("Updating %s record %s of domain %s%s.",
                             record_type, record_name, domain,
                             ' with content '+record_content if record_content is not None else '')
            records = self.get_records(domain, record_type, record_name, old_record_content)
            if len(records)==0:
                raise HoverClientException(self, "Requested %s record %s for domain %s%s does not exist.",
                                           record_type, record_name, domain,
                                           ' with content '+old_record_content if old_record_content is not None else '')
            elif len(records)>1 and old_record_content is None:
                raise HoverClientException(self, "Requested %s record %s for domain %s exists multiple times but no current content was given.",
                                           record_type, record_name, domain)
            else:
                for record in records:
                    data = [('content',record_content)]
                    if record_ttl is not None:
                        data.append(('ttl',record_ttl))
                    recId= record.get('id')
                    self.logger.debug("  Updating existing record under id %s", recId)
                    self._request('PUT','api/dns/{0}'.format(recId),'update DNS record', data=data)
                self.logger.debug('  -> successfully updated %d records.', len(records))
        except BaseException as ex:
            raise HoverClientException(self, "%s -> Failed to update %s record %s of domain %s%s.",
                                       str(ex), record_type, record_name, domain,
                                       ' with content '+record_content if record_content is not None else '',
                                      ) from ex


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
    # client.add_record('schaeckermann.net', 'TXT', 'hugo.schaeckermann.net', 'emil')
    # client.add_record('schaeckermann.net', 'TXT', 'hugo.schaeckermann.net', 'anna')
    # client.update_record('schaeckermann.net', 'TXT', 'hugo', 'anna', old_record_content='emil', record_ttl=300)
    # client.delete_record('schaeckermann.net', 'TXT', 'hugo.schaeckermann.net', 'anna')
    # client.logout()

    client.add_record('doesnotexist.com', 'TXT', 'hugo', 'emil')
    client.logout()
