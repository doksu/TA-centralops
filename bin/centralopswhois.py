#!/usr/bin/env python

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from StringIO import StringIO
import sys
import os
import socket
import urllib2
import re
import gzip
import ConfigParser


@Configuration()
class CentralOpsWhoisCommand(StreamingCommand):
    """ 

    ##Syntax


    ##Description


    ##Example


    """

    limit = Option(require=False, validate=validators.Integer(minimum=1))

    def stream(self, events):

        if len(self.fieldnames) != 1:
            raise Exception("Please provide a single field")

        default_limit = 5
        try:
            configparser = ConfigParser.ConfigParser()
            configparser.read(os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/TA-centralops/local/centralops.conf'))
            
            if configparser.has_section('general'): 
                if configparser.has_option('general', 'limit'):
                    config_value = configparser.get('general', 'limit')
                    if config_value.isdigit() and config_value > 0:
                        default_limit = config_value
                        del config_value

        except:
           pass

        proxies = {'http': None, 'https': None}
        try:
            configparser = ConfigParser.ConfigParser()
            configparser.read(os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/TA-centralops/local/centralops.conf'))

            if configparser.has_section('proxies'):
                if configparser.has_option('proxies', 'http'):
                   if len(configparser.get('proxies', 'http')) > 0:
                       proxies['http'] = configparser.get('proxies', 'http')
                if configparser.has_option('proxies', 'https'):
                   if len(configparser.get('proxies', 'https')) > 0:
                       proxies['https'] = configparser.get('proxies', 'https')

        except:
            pass

        if self.limit:
            limit = self.limit
        else:
            limit = default_limit

        url = "https://centralops.net/co/DomainDossier.aspx"
        headers = {"Connection": "keep-alive", "Cache-Control": "max-age=0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0", "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US;q=0.6,en;q=0.4"}

        threshold = 0
        for event in events:

            if threshold == limit:
               yield event
               continue

            if self.fieldnames[0] in event:

                parameters = "addr=" + str(event[self.fieldnames[0]]) + "&dom_whois=true"
                request = urllib2.Request(url)

                for key in headers:
                    request.add_header(key, headers[key])

                request.add_data(parameters)

                if proxies['http'] is not None or proxies['https'] is not None:
                    proxy = urllib2.ProxyHandler(proxies)
                    opener = urllib2.build_opener(proxy)
                    urllib2.install_opener(opener)

                try:
                    response = urllib2.urlopen(request, timeout=3)
                    threshold += 1
                except:
                    raise Exception("Failed to connect to centralops.net - please check TA-centralops app proxy settings")

                if response.getcode()==200:
                    if response.info().getheader("Content-Encoding")=="gzip":
                        data = StringIO(response.read())
                        gzipobject = gzip.GzipFile(fileobj=data)
                        page = gzipobject.read()
                    else:
                        page = response.read()

                    extracts = re.findall(r'^(\w[\w\s]+):\s+(\S+.+)\r', page, re.MULTILINE)

                    extract_dict = {}
                    for kv_pair in extracts:
                        key = str(self.fieldnames[0] + "_" + kv_pair[0].replace(" ", "_").lower())
                        try:
                            extract_dict[key] = extract_dict[key] + [str(kv_pair[1])]
                        except:
                            extract_dict[key] = [str(kv_pair[1])]

                    for key in extract_dict:
                        event[key] = extract_dict[key]
                else:
                    raise Exception("Received http response code status=" + str(response.getcode()) + " from centralops.net - please check your query limit hasn't been reached")

                yield event

            else:
                continue

dispatch(CentralOpsWhoisCommand, sys.argv, sys.stdin, sys.stdout, __name__)
