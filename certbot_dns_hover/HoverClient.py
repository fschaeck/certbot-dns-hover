#!python3
"""
This module provides the class HoverClient that encapsulates the
DNS admin API at https://www.hover.com
"""

import os
import sys
import logging
import base64
import hashlib
import hmac
import calendar
import datetime
import time
import re
import json
import argparse

import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

__VERSION__ = "1.2.4"

class HoverClientException(Exception):
    def __init__(self, logger, msg, *args):
        self.msg = msg % args
        super().__init__(self.msg)
        logger.error(self.msg)


class Session:
    def __init__(self, base_url, logger):
        self.logger = logger
        self.base_url = base_url
        self.base_url_domain = re.sub('^https?://[^.]+\\.([^/]+)/.*$','\\1',base_url)
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': base_url
                }


    def clear_cookies(self):
        self.cookie_jar.clear()


    def set_cookie(self, cookie):
        self.cookie_jar.set_cookie(cookie)


    def get_cookie(self, cookie_name):
        for cookie in self.cookie_jar:
            if cookie.name==cookie_name:
                return cookie.value
        return None


    def request(self, method, action, action_description, referer=None, data=None, ignore_result=False):
        try:
            url = "{0}/{1}".format(self.base_url,action.lstrip('/'))
            self.logger.debug("    %s request to URL %s to %s", method, url, action_description)
            if data==None:
                req_data = None
                self.headers.pop('Content-Type',None);
            elif isinstance(data,dict):
                req_data = json.dumps(data).encode('utf-8')
                self.headers['Content-Type'] = 'application/json; charset=utf-8'
            elif isinstance(data,list):
                req_data = urllib.parse.urlencode(data).encode('utf-8')
                self.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'

            if referer!=None:
                self.headers['Referer'] = "{0}/{1}".format(self.base_url,referer.lstrip('/')) if referer else self.base_url

            req = urllib.request.Request(url, data=req_data, headers=self.headers, method=method)
            try:
                with self.opener.open(req) as response:
                    result_raw = response.read()
                    if response.getcode() != 200:
                       if result_raw!=None and len(result_raw)>0:
                           raise HoverClientException(self.logger, "%s request to URL %s to %s failed with HTTP error %d and message %s",
                                                      method, url, action_description, response.getcode(), result_raw)
                       else:
                           raise HoverClientException(self.logger, "%s request to URL %s to %s failed with HTTP error %d",
                                                      method, url, action_description, response.getcode())
                    self.logger.debug('      returned 200')
                    if ignore_result:
                        return {}
                    else:
                        try:
                            result = json.loads(result_raw)
                        except:
                            raise HoverClientException(self.logger, "%s request to URL %s to %s responded with non JSON data: %s",
                                                       method, url, action_description, result_raw)

                        if result.get("succeeded",False)==True or result.get("status","")=="need_2fa":
                            self.logger.debug('      -> request succeeded:\n%s', result_raw)
                            return result
                        else:
                            raise HoverClientException(self.logger, "%s request to URL %s to %s was unsuccessful: %s",
                                                       method, url, action_description, result_raw)
            except urllib.error.HTTPError as e:
                raise HoverClientException(self.logger, "%s request to URL %s to %s failed with HTTP error %d: %s",
                                           method, url, action_description, e.code, e.read())
        except HoverClientException:
            raise
        except BaseException as ex:
            raise HoverClientException(self.logger, "%s -> Failed to %s.", str(ex), action_description) from ex;


class HoverClient(object):
    """
    Encapsulates all communication with the Hover Domain Administration REST API.
    """

    def __init__(self, hover_base_url, username, password, totpsecret, logger=None, log_level=logging.ERROR):
        if logger is None:
            logging.basicConfig(level=log_level)
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        self.logger.info("Creating HoverClient v%s", __VERSION__)
        self.username = username
        self.password = password
        self.totpsecret = totpsecret
        self.session = Session(hover_base_url,self.logger)
        self.loggedIn = None
        self.domains = None

    def get_cookies(self):
        return [ {'version': cookie.version,
                  'name': cookie.name,
                  'value': cookie.value,
                  'port': cookie.port,
                  'domain': cookie.domain,
                  'path': cookie.path,
                  'secure': cookie.secure,
                  'expires': cookie.expires,
                  'discard': cookie.discard,
                  'comment': cookie.comment,
                  'comment_url': cookie.comment_url,
                  'rfc2109': cookie.rfc2109,
                  'port_specified': cookie.port_specified,
                  'domain_specified': cookie.domain_specified,
                  'domain_initial_dot': cookie.domain_initial_dot,
                 } for cookie in self.session.cookie_jar ]

    def _login(self):
        try:
            if self.loggedIn is not None:
                if time.monotonic()-self.loggedIn<120.0: # only double-check every two minutes
                    self.logger.debug('Already logged in.')
                    return
                try:
                    # check if the login is still valid
                    self.logger.debug('Checking login status.')
                    self.session.request('GET','api/domains','check login',ignore_result=True)
                    self.logger.debug('Login confirmed.')
                    self.loggedIn = time.monotonic()
                    return
                except:
                    # if there was a problem - redo the login
                    self.logger.debug('Re-doing login.')
                    self.loggedIn = None

            self.logger.info('Logging in as %s', self.username)
            self.session.clear_cookies();
            self.session.set_cookie(http.cookiejar.Cookie(
                version=0,
                name='hover_device_id',
                value='0031160fdac747e83248',
                port=None,
                port_specified=False,
                domain='www.hover.com',
                domain_specified=False,
                domain_initial_dot=False,
                path='/signin',
                path_specified=True,
                secure=False,
                expires=time.time()+315532800,
                discard=False,
                comment=None,
                comment_url=None,
                rfc2109=False, 
                rest={}))

            # Login start: initializing cookie hover_session
            self.session.request('GET', 'signin', 'initialize login session', referer="", ignore_result=True)

            if self.session.get_cookie('hover_session') is None:
                raise HoverClientException(self.logger, "Failed to initialize login session. No cookie 'hover_session' found.")

            # Login phase 1: username and password
            result = self.session.request('POST','signin/auth.json','login with user name and password',
                                          referer='signin',
                                          data={'username':self.username,
                                                'password':self.password,
                                                'token': None })

            if result.get("status", "")!="need_2fa":
                raise HoverClientException(self.logger, "Status 'need_2fa' expected but got %s.",result.get("status"))

            # Login phase 2: Timebased OTP Token
            result = self.session.request('POST','signin/auth2.json','authenticate with TOTP token',
                                          referer='signin/auth.json',
                                          data={'code': self._get_totp_token()})

            self.logger.info('Successfully logged in as %s.', self.username)
            self.loggedIn = time.monotonic()

            if self.domains==None:
                result = self.session.request('GET', 'api/domains', 'retrieve domain list', referer='control_panel')
                self.domains = {}
                for domain in result.get('domains',{}):
                    self.domains[domain['domain_name']] = domain

        except BaseException as ex:
            raise HoverClientException(self.logger, '%s -> Failed to log in as %s.', str(ex), self.username) from ex


    def logout(self):
        '''
        If an active session exists, it does a logout from the API
        and closes the session. Any exceptions are willfully ignored.
        '''
        if self.loggedIn is not None:
            try:
                self.logger.info('Closing Hover Client session')
                self.session.request('GET', 'logout', 'logout', ignore_result=True)
                self.logger.info('  Successfully logged out.')
            except BaseException as ex:
                self.logger.warning('  Failed to logout: %s', ex)
            finally:
                self.loggedIn = None


    def get_root_domain(self, domain):
        self.logger.debug('  looking for root domain for %s', domain)
        self._login()
        root_domain = domain
        while not root_domain in self.domains:
            dot = root_domain.find('.')
            if dot<0:
                self.logout()
                raise HoverClientException(self.logger, "Can not find root domain for %s", domain)
            else:
                root_domain = root_domain[dot+1:]
        self.logger.debug('  --> %s', root_domain)
        return root_domain


    def get_records(self, domain, record_type, record_name, record_content=None):
        try:
            self.logger.debug('  looking for %s records %s from domain %s%s',
                              record_type, record_name, domain,
                              ' with content {0}'.format(record_content) if record_content is not None else '')

            self._login()
            if not domain in self.domains:
                domain = self.get_root_domain(domain)

            domain_dns_list = self.session.request('GET', 'api/domains/{0}/dns'.format(domain), 'retrieve DNS records', referer='control_panel')

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
            raise HoverClientException(self.logger, '%s -> Failed to retrieve %s records %s from domain %s%s.',
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
                self.session.request('POST','api/domains/{0}/dns'.format(domain),
                                     'insert new DNS record',
                                     data={'content':    record_content,
                                           'name':       record_name,
                                           'type':       record_type,
                                           'ttl':        record_ttl,
                                          })
                records = self.get_records(domain, record_type, record_name, record_content)
                if len(records)==0:
                    raise HoverClientException(self.logger, "Something went wrong when adding %s record %s for domain %s even though there was no error reported.",
                                               record_type, record_name, domain)
                else:
                    self.logger.debug('  -> successfully inserted new record')
            else:
                self.logger.debug("  -> record exists already under id %s", records[0].get('id'))
        except BaseException as ex:
            self.logout()
            raise HoverClientException(self.logger, "%s -> Failed to ensure %s record %s for domain %s with content %s exists.",
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
                    recId = record.get('id')
                    self.logger.debug("  Deleting existing record under id %s", recId)
                    self.session.request('DELETE','api/dns/{0}'.format(recId), 'delete DNS record')
                self.logger.debug('  -> successfully deleted %d records.', len(records))
        except BaseException as ex:
            self.logout()
            raise HoverClientException(self.logger, "%s -> Failed to ensure all %s records %s of domain %s%s are deleted",
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
                raise HoverClientException(self.logger, "Requested %s record %s for domain %s%s does not exist.",
                                           record_type, record_name, domain,
                                           ' with content '+old_record_content if old_record_content is not None else '')
            elif len(records)>1 and old_record_content is None:
                raise HoverClientException(self.logger, "Requested %s record %s for domain %s exists multiple times but no current content was given.",
                                           record_type, record_name, domain)
            else:
                for record in records:
                    data = [('content',record_content)]
                    if record_ttl is not None:
                        data.append(('ttl',record_ttl))
                    recId = record.get('id')
                    self.logger.debug("  Updating existing record under id %s", recId)
                    self.session.request('PUT','api/dns/{0}'.format(recId),'update DNS record', data=data)
                self.logger.debug('  -> successfully updated %d records.', len(records))
        except BaseException as ex:
            self.logout()
            raise HoverClientException(self.logger, "%s -> Failed to update %s record %s of domain %s%s.",
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
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd',        action='store', type=str, choices=['add','delete','update'], help='Command to execute')
    ap.add_argument('type',       action='store', type=str, choices=['TXT','MX','CNAME','A','AAAA'], help='Type of record to process')
    ap.add_argument('domain',     action='store', type=str, help='Domain to execute against')
    ap.add_argument('name',       action='store', type=str, help='Name of record to process')
    ap.add_argument('value',      action='store', type=str, help='Value to add, delete or update to')
    ap.add_argument('-t','--ttl', action='store', type=int, default=900, help='TTL value for record')
    ap.add_argument('-u','--update', action='store', type=str, required=False, help='Old value to update from')
    ap.add_argument('-d','--debug', action='store_true', required=False, default=False, help='Produce debugging output')
    args = ap.parse_args()

    user_name = os.getenv('HOVER_USER_NAME')
    user_pwd  = os.getenv('HOVER_USER_PASSWORD')
    user_totp = os.getenv('HOVER_USER_TOTPSECRET')

    if user_name is None:
        print("Environment variable HOVER_USER_NAME not set. Aborting...",file=sys.stderr)
        sys.exit(1)

    if user_pwd is None:
        print("Environment variable HOVER_USER_PASSWORD not set. Aborting...",file=sys.stderr)
        sys.exit(1)

    if user_totp is None:
        print("Environment variable HOVER_USER_TOTPSECRET not set. Aborting...",file=sys.stderr)
        sys.exit(1)

    try:
        if args.debug:
            client = HoverClient('https://www.hover.com', user_name, user_pwd, user_totp, log_level=logging.DEBUG)
        else:
            client = HoverClient('https://www.hover.com', user_name, user_pwd, user_totp)

        root_domain = client.get_root_domain(args.domain)
        record_name = args.name
        if record_name.endswith('.'+root_domain):
            record_name = record_name[:-len(root_domain)-1]

        if args.cmd == 'add':
            client.add_record(root_domain, args.type, record_name, args.value, record_ttl=args.ttl)
        elif args.cmd == 'update':
            client.update_record(root_domain, args.type, record_name, args.value, old_record_content=args.update, record_ttl=args.ttl)
        elif args.cmd == 'delete':
            client.delete_record(root_domain, args.type, record_name, args.value)
    except Exception as e:
        print("ERROR: %s" % str(e), file=sys.stderr)
    finally:
        client.logout()
