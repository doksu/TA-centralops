#!/usr/bin/env python

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import sys
import os
import socket
import re
import gzip
import json
import time
try:
    # python2
    import ConfigParser as configparser
    from StringIO import StringIO as BytesIO
    import urllib2 as urllib_functions
except:
    # python3
    import configparser
    from io import BytesIO
    import urllib.request as urllib_functions

@Configuration()
class CentralOpsWhoisCommand(StreamingCommand):
    """ 

    ##Syntax


    ##Description


    ##Example


    """

    limit = Option(require=False, validate=validators.Integer(minimum=1))
    output = Option(require=False)

    def stream(self, events):

        cache = {}

        if len(self.fieldnames) != 1:
            raise Exception("Please provide a single field")

        if self.output:
            if self.output not in ("fields", "json"):
                raise Exception("Invalid output format")
        else:
            self.output = "fields"

        default_limit = 5
        general_config = None
        try:
            general_config = ConfigParser.ConfigParser()
            general_config.read(os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/TA-centralops/local/centralops.conf'))
        except:
            pass

        # let's try reading the default config (to support Search Head Clusters where local configs are merged into default)
        try:
            general_config = ConfigParser.ConfigParser()
            general_config.read(os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/TA-centralops/default/centralops.conf'))
        except:
            pass
        
        if not general_config == None:
            if general_config.has_section('general'): 
                if general_config.has_option('general', 'limit'):
                    general_config_value = general_config.get('general', 'limit')
                    if general_config_value.isdigit() and general_config_value > 0:
                        default_limit = general_config_value
                        del general_config_value

        proxies = {'http': None, 'https': None}
        proxies_config = None
        try:
            proxies_config = ConfigParser.ConfigParser()
            proxies_config.read(os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/TA-centralops/local/centralops.conf'))

        except:
            pass

        # let's try reading the default config (to support Search Head Clusters where local configs are merged into default)
        try:
            if not proxies_config == None:
               proxies_config = ConfigParser.ConfigParser()
               proxies_config.read(os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/TA-centralops/default/centralops.conf'))

        except:
            pass

        if not proxies_config == None:
            if proxies_config.has_section('proxies'):
                if proxies_config.has_option('proxies', 'http'):
                   if len(proxies_config.get('proxies', 'http')) > 0:
                       proxies['http'] = proxies_config.get('proxies', 'http')
                if proxies_config.has_option('proxies', 'https'):
                   if len(proxies_config.get('proxies', 'https')) > 0:
                       proxies['https'] = proxies_config.get('proxies', 'https')

        if self.limit:
            limit = self.limit
        else:
            limit = default_limit

        url = "https://centralops.net/co/DomainDossier.aspx"
        headers = {"Connection": "keep-alive", "Cache-Control": "max-age=0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0", "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US;q=0.6,en;q=0.4"}

        threshold = 0
        for event in events:

            # if the event's whois information has already been found in the lookup cache
            if "updated" in event:
               if str(event["updated"]) != "":
                   yield event
                   continue

            if threshold == limit:
               yield event
               continue

            if self.fieldnames[0] in event:

                try:
                    extracts = cache[str(event[self.fieldnames[0]])]

                except:

                    if threshold > 0:
                        time.sleep(1.4)

                    # if the query is for an ip address
                    if re.match('^\d+\.\d+.\d+\.\d+$', event[self.fieldnames[0]]):
                        parameters = "addr=" + str(event[self.fieldnames[0]]) + "&net_whois=true"
                    else:
                        parameters = "addr=" + str(event[self.fieldnames[0]]) + "&dom_whois=true"

                    request = urllib_functions.Request(url)

                    for key in headers:
                        request.add_header(key, headers[key])

                    request.data = parameters.encode("utf-8")

                    if proxies['http'] is not None or proxies['https'] is not None:
                        proxy = urllib_functions.ProxyHandler(proxies)
                        opener = urllib_functions.build_opener(proxy)
                        urllib_functions.install_opener(opener)

                    try:
                        response = urllib_functions.urlopen(request, timeout=3)
                        threshold += 1
                    except:
                        raise Exception("Failed to connect to centralops.net - please check TA-centralops app proxy settings")

                    if response.getcode()==200:
                        if response.getheader("Content-Encoding")=="gzip":
                            data = BytesIO(response.read())
                            gzipobject = gzip.GzipFile(fileobj=data)
                            page = gzipobject.read()
                        else:
                            page = response.read()

                        extracts = re.findall(b'^(?:<pre>)?(\w[\w\s]+):\s+(\S+.+)\r', page, re.MULTILINE)
                        cache[str(event[self.fieldnames[0]])] = extracts

                    else:
                        raise Exception("Received http response code status=" + str(response.getcode()) + " from centralops.net - please check your query limit hasn't been reached")

                extract_dict = {}
                prefix = str(self.fieldnames[0] + "_")

                for kv_pair in extracts:

                    # convert byte tuple to list of utf-8 strings
                    kv_pair = [kv_pair[0].decode('utf-8', 'ignore'), kv_pair[1].decode('utf-8', 'ignore')]

                    if self.output == "json":
                        key = str(kv_pair[0].replace(" ", "_").lower())
                    else:
                        key = str(prefix + kv_pair[0].replace(" ", "_").lower())

                    try:
                        extract_dict[key] = extract_dict[key] + [str(kv_pair[1])]
                    except:
                        extract_dict[key] = [str(kv_pair[1])]

                for key in extract_dict:
                    if len(extract_dict[key]) == 1:
                        extract_dict[key] = extract_dict[key][0]

                if self.output == "json":
                    extract_dict["resolved_domain"] = str(event[self.fieldnames[0]])
                    event[prefix + "whois"] = json.dumps(extract_dict)
                        
                else:
                    for key in extract_dict:
                        event[key] = extract_dict[key]

                yield event

            else:
                continue

dispatch(CentralOpsWhoisCommand, sys.argv, sys.stdin, sys.stdout, __name__)
