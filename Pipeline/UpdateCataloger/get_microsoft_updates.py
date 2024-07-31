#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

# Script to search for updates in the Microsoft Update Catalog. Works on both Python 2 and 3 but requires BeautifulSoup
# to be installed - https://www.crummy.com/software/BeautifulSoup/#Download

import contextlib
import datetime
import json
import re
import uuid
from bs4 import BeautifulSoup
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

CATALOG_URL = 'https://www.catalog.update.microsoft.com/'
DOWNLOAD_PATTERN = re.compile(r'\[(\d*)\]\.url = [\"\'](https://catalog\.s\.download\.windowsupdate\.com/[^\'\"\\]*)')
PRODUCT_SPLIT_PATTERN = re.compile(r',(?=[^\s])')

@contextlib.contextmanager
def fetch_url(url, data=None, headers=None):
    resp = urlopen(Request(url, data=data, headers=headers))
    try:
        yield resp
    finally:
        resp.close()

# Cache for the catalog ID download results url
CATALOG_ID_CACHE = {}

def load_cache(name="catalogUpdaterCache.json"):
    import os
    try:
        if os.path.exists(name):
            with open(name, 'r') as f:
                global CATALOG_ID_CACHE
                CATALOG_ID_CACHE = json.load(f)
    except (IOError, ValueError):
        return {}

def save_cache(name="catalogUpdaterCache.json"):
    with open(name, 'w') as f:
        global CATALOG_ID_CACHE
        json.dump(CATALOG_ID_CACHE, f)

# intercept any kill signal and store the cache
import signal
import sys

def signal_handler(sig, frame):
    print(f"Caught signal {sig}, saving cache and exiting")
    save_cache()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGQUIT, signal_handler)
signal.signal(signal.SIGABRT, signal_handler)

def createWUDownloadInfo(data):
    wu = WUDownloadInfo('', '', '')
    wu.fromJson(data)
    return wu

class WUDownloadInfo:

    def __init__(self, download_id, url, raw):
        """
        Contains information about an individual download link for an update. An update might have multiple download
        links available and this keeps track of the metadata for each of them.

        :param download_id: The ID that relates to the download URL.
        :param url: The download URL for this entry.
        :param raw: The raw response text of the downloads page.
        """
        self.url = url
        self.digest = None
        self.architectures = None
        self.languages = None
        self.long_languages = None
        self.file_name = None

        attribute_map = {
            'digest': 'digest',
            'architectures': 'architectures',
            'languages': 'languages',
            'long_languages': 'longLanguages',
            'file_name': 'fileName',
        }
        for attrib_name, raw_name in attribute_map.items():
            regex_pattern = r"\[%s]\.%s = ['\"]([\w\-\.=+\/\(\) ]*)['\"];" \
                            % (re.escape(download_id), re.escape(raw_name))
            regex_match = re.search(regex_pattern, raw)
            if regex_match:
                setattr(self, attrib_name, regex_match.group(1))

    def __str__(self):
        return "%s - %s" % (self.file_name or "unknown", self.long_languages or "unknown language")


class WindowsUpdate:

    def __init__(self, raw_element):
        """
        Stores information about a Windows Update entry.

        :param raw_element: The raw XHTML element that has been parsed by BeautifulSoup4.
        """
        cells = raw_element.find_all('td')

        self.title = cells[1].get_text().strip()

        # Split , if there is no space ahead.
        products = cells[2].get_text().strip()
        self.products = list(filter(None, re.split(PRODUCT_SPLIT_PATTERN, products)))

        self.classification = cells[3].get_text().strip()
        self.last_updated = datetime.datetime.strptime(cells[4].get_text().strip(), '%m/%d/%Y')
        self.version = cells[5].get_text().strip()
        self.size = int(cells[6].find_all('span')[1].get_text().strip())
        self.id = uuid.UUID(cells[7].find('input').attrs['id'])
        self.exists_in_cache = str(self.id) in CATALOG_ID_CACHE
        self._details = None
        self._architecture = None
        self._description = None
        self._download_urls = None
        self._kb_numbers = None
        self._more_information = None
        self._msrc_number = None
        self._msrc_severity = None
        self._support_url = None

    @property
    def architecture(self):
        """ The architecture of the update. """
        if not self._architecture:
            details = self._get_details()
            raw_arch = details.find(id='ScopedViewHandler_labelArchitecture_Separator')
            self._architecture = raw_arch.next_sibling.strip()

        return self._architecture

    @property
    def description(self):
        """ The description of the update. """
        if not self._description:
            details = self._get_details()
            self._description = details.find(id='ScopedViewHandler_desc').get_text()

        return self._description

    @property
    def download_url(self):
        """ The download URL of the update, will fail if the update contains multiple packages. """
        download_urls = self.get_download_urls()

        if len(download_urls) != 1:
            raise ValueError("Expecting only 1 download link for '%s', received %d. Use get_download_urls() and "
                             "filter it based on your criteria." % (str(self), len(download_urls)))

        return download_urls[0].url

    @property
    def kb_numbers(self):
        """ A list of KB article numbers that apply to the update. """
        if self._kb_numbers is None:
            details = self._get_details()
            raw_kb = details.find(id='ScopedViewHandler_labelKBArticle_Separator')

            # If no KB's apply then the value will be n/a. Technically an update can have multiple KBs but I have
            # not been able to find an example of this so cannot test that scenario.
            self._kb_numbers = [int(n.strip()) for n in list(raw_kb.next_siblings) if n.strip().lower() != 'n/a']

        return self._kb_numbers

    @property
    def more_information(self):
        """ Typically the URL of the KB article for the update but it can be anything. """
        if self._more_information is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelMoreInfo_Separator')
            self._more_information = list(raw_info.next_siblings)[1].get_text().strip()

        return self._more_information

    @property
    def msrc_number(self):
        """ The MSRC Number for the update, set to n/a if not defined. """
        if self._msrc_number is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSecurityBulliten_Separator')
            self._msrc_number = list(raw_info.next_siblings)[0].strip()

        return self._msrc_number

    @property
    def msrc_severity(self):
        """ THe MSRC severity level for the update, set to Unspecified if not defined. """
        if self._msrc_severity is None:
            details = self._get_details()
            self._msrc_severity = details.find(id='ScopedViewHandler_msrcSeverity').get_text().strip()

        return self._msrc_severity

    @property
    def support_url(self):
        """ The support URL for the update. """
        if self._support_url is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSupportUrl_Separator')
            self._support_url = list(raw_info.next_siblings)[1].get_text().strip()

        return self._support_url

    def done(self):
        CATALOG_ID_CACHE[str(self.id)] = self.size

    def get_download_urls(self):
        """
        Get a list of WUDownloadInfo objects for the current update. These objects contain the download URL for all the
        packages inside the update.
        """
        if self._download_urls is None:
            update_ids = json.dumps({
                'size': 0,
                'updateID': str(self.id),
                'uidInfo': str(self.id),
            })
            data = urlencode({'updateIDs': '[%s]' % update_ids}).encode('utf-8')

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            with fetch_url('%s/DownloadDialog.aspx' % CATALOG_URL, data=data, headers=headers) as resp:
                resp_text = resp.read().decode('utf-8').strip()

            link_matches = re.findall(DOWNLOAD_PATTERN, resp_text)
            if len(link_matches) == 0:
                raise ValueError("Failed to find any download links for '%s'" % str(self))

            download_urls = []
            for download_id, url in link_matches:
                download_urls.append(WUDownloadInfo(download_id, url, resp_text))

            self._download_urls = download_urls

        return self._download_urls

    def _get_details(self):
        if not self._details:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            with fetch_url('%s/ScopedViewInline.aspx?updateid=%s' % (CATALOG_URL, str(self.id)),
                           headers=headers) as resp:
                resp_text = resp.read().decode('utf-8').strip()
            self._details = BeautifulSoup(resp_text, 'html.parser')

        return self._details

    def __str__(self):
        return self.title


def find_updates(search, all_updates=False, sort=None, sort_reverse=False, data=None):
    """
    Generator function that yields WindowsUpdate objects for each update found on the Microsoft Update catalog.
    Yields a list of updates from the Microsoft Update catalog. These updates can then be downloaded locally using the
    .download(path) function.

    :param search: The search string used when searching the update catalog.
    :param all_updates: Set to True to continue to search on all pages and not just the first 25. This can dramatically
        increase the runtime of the script so use with caution.
    :param sort: The field name as seen in the update catalog GUI to sort by. Setting this will result in 1 more call
        to the catalog URL.
    :param sort_reverse: Reverse the sort after initially sorting it. Setting this will result in 1 more call after
        the sort call to the catalog URL.
    :param data: Data to post to the request, used when getting all pages
    :return: Yields the WindowsUpdate objects found.
    """
    if len(CATALOG_ID_CACHE) == 0:
        load_cache()

    search_safe = quote(search)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    if data:
        data = urlencode(data).encode('utf-8')

    url = '%s/Search.aspx?q=%s' % (CATALOG_URL, search_safe)
    with fetch_url(url, data=data, headers=headers) as resp:
        resp_text = resp.read().decode('utf-8').strip()

    if "We did not find any results for " in resp_text:
        print(f"[I] No results found for '{search}'")
        return

    if "Your search resulted in over 1000 matching updates." in resp_text:
        print(f"[I] Too many results found for '{search}', please refine your search")
        return

    catalog = BeautifulSoup(resp_text, 'html.parser')

    # If we need to perform an action (like sorting or next page) we need to add these 4 fields that are based on the
    # original response received.
    def build_action_data(action):
        data = {
            '__EVENTTARGET': action,
        }
        for field in ['__EVENTARGUMENT', '__EVENTVALIDATION', '__VIEWSTATE', '__VIEWSTATEGENERATOR']:
            element = catalog.find(id=field)
            if element:
                data[field] = element.attrs['value']

        return data

    raw_updates = catalog.find(id='ctl00_catalogBody_updateMatches').find_all('tr')
    headers = raw_updates[0]  # The first entry in the table are the headers which we may use for sorting.

    if sort:
        # Lookup the header click JS targets based on the header name to sort.
        header_links = headers.find_all('a')
        event_targets = dict((l.find('span').get_text(), l.attrs['id'].replace('_', '$')) for l in header_links)
        data = build_action_data(event_targets[sort])

        sort = sort if sort_reverse else None  # If we want to sort descending we need to sort it again.
        for update in find_updates(search, all_updates, sort=sort, data=data):
            yield update
        return

    for u in raw_updates[1:]:
        yield WindowsUpdate(u)

    # ctl00_catalogBody_nextPage is set when there are no more updates to retrieve.
    last_page = catalog.find(id='ctl00_catalogBody_nextPage')
    if not last_page and all_updates:
        data = build_action_data('ctl00$catalogBody$nextPageLinkText')
        for update in find_updates(search, True, data=data):
            yield update