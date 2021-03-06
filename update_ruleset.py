#!/usr/bin/env python3
"""
Get all rulesets type active_checks:http, format new rule, add to existent ruleset and then update ruleset with configuration_hash received

To obtain ruleset types:
curl -k 'https://mycheckmk/mysite/check_mk/webapi.py?action=get_rulesets_info&_username=myuser&_secret=password&request_format=python&output_format=json'|jq

Usage:
export CHECKMK_USER=myuser
export CHECKMK_PASSWORD=mypassword
export CHECKMK_URL=https://mycheckmk/mysite
update_ruleset.py myhost mymonitor 10.10.10.10 8080 /myapp

Checkmk version: 1.6.0p18
"""
import datetime
import logging
import os
from urllib import request, parse
import ssl
import sys
import ast

ssl._create_default_https_context = ssl._create_unverified_context
logging.basicConfig(
    format="%(asctime)s:%(levelname)s:%(message)s", datefmt="%d/%m/%Y %H:%M:%S"
)
logging.getLogger().setLevel(logging.INFO)


CHECKMK_USER = os.getenv("CHECKMK_USER", "myuser")
CHECKMK_PASSWORD = os.getenv("CHECKMK_PASSWORD", "mypassword")
CHECKMK_URL = os.getenv("CHECKMK_URL", "https://mycheckmk/mysite")
CHECKMK_SITE = CHECKMK_URL.split("/")[-1]

RULESET_NAME = "active_checks:http"

path_activate_changes = "/check_mk/webapi.py?action=activate_changes"
path_get_rule = "/check_mk/webapi.py?action=get_ruleset"
path_set_rule = "/check_mk/webapi.py?action=set_ruleset"
params_auth = f"&_username={CHECKMK_USER}&_secret={CHECKMK_PASSWORD}"
params_format = "&request_format=python&output_format=python"
params_ruleset_name = "&ruleset_name=" + RULESET_NAME


def get_url_activate_changes():
    """Return url activate_changes"""
    return CHECKMK_URL + path_activate_changes + params_auth + params_format


def get_url_get_rule():
    """Return url get_rule"""
    return (
        CHECKMK_URL + path_get_rule + params_auth + params_format + params_ruleset_name
    )


def get_url_set_rule():
    """Return url set_rule"""
    return (
        CHECKMK_URL + path_set_rule + params_auth + params_format + params_ruleset_name
    )


def convert_string_python2(request_string):
    """
    python2: print(repr(u'\xf4')) -> u'\xf4
    python3: print(repr(u'\xf4')) -> '??'
    In order to Checkmk accept the new ruleset, this function convert all non-ascii chars to corresponding hex escaped as Python 2 usually does
    Otherwise, will return the error 'Check_MK exception: ERROR: Non-ASCII characters are not allowed here.'
    Excerpted from:
    https://github.com/tribe29/checkmk/blob/e75552431ae27be29b248e65bf7afdcfda03d83d/cmk/utils/python_printer.py
    """
    chars: List[str] = []
    for c in request_string:
        if ord(c) > 127:
            chars.append("\\x{:02x}".format(ord(c)))
        else:
            chars.append(str(c))

    request_string = "".join(chars)
    request_string = request_string.replace("'name': ", "'name': u")
    request_string = request_string.replace("'comment': ", "'comment': u")
    request_string = request_string.replace("'expect_string': ", "'expect_string': u")
    return request_string


def create_rule(host_name, monitor):
    """Create new rule
    Example:
    {
    'condition': {'host_name': ['hostname']},
    'options': {   'comment': 'Created in ...'},
    'value': {  'host': {
                    'address': '10.10.10.10',
                    'port': 80,
                    'virthost': '10.10.10.10'
                    },
                'mode': (   'url',
                        {   'expect_string': '',
                            'onredirect': 'follow',
                            'timeout': 30,
                            'uri': '/',
                            'urlize': True}
                        ),
                'name': '^name'
            }
        }
    """
    new_rule = {}
    condition = {}
    condition["host_name"] = host_name
    new_rule["condition"] = condition

    now = datetime.datetime.now()
    now_fmt = now.strftime("%d/%m/%Y %H:%M:%S")

    options = {}
    options["comment"] = f"Created in {now_fmt}"
    new_rule["options"] = options

    value = {}
    host = {}
    host["address"] = monitor["url"]
    host["port"] = monitor["port"]
    host["virthost"] = monitor["url"]
    value["host"] = host

    attrs = {}
    attrs["method"] = "GET"
    attrs["onredirect"] = "follow"
    attrs["timeout"] = 30
    attrs["uri"] = monitor["uri"]
    if host["port"] == "443":
        attrs["ssl"] = "auto"
    attrs["urlize"] = True
    mode = ("url", attrs)

    value["mode"] = mode
    value["name"] = "^" + monitor["name"]
    new_rule["value"] = value
    return new_rule


def update_ruleset(ruleset, config_hash):
    """Add ruleset to existing one"""
    logging.info("Sending new ruleset {}".format(RULESET_NAME))
    logging.info("Requesting URL: {}".format(get_url_set_rule()))
    req = {}
    req["ruleset_name"] = RULESET_NAME
    resp_ruleset = {}
    resp_ruleset[""] = ruleset
    req["ruleset"] = resp_ruleset
    req["configuration_hash"] = config_hash
    request_string = "request=" + convert_string_python2(repr(req))
    request_string = parse.quote(request_string, safe='{[]}"=, :')
    req = request.Request(get_url_set_rule(), request_string.encode())
    resp = request.urlopen(req)
    return resp.read()


def get_ruleset_confighash():
    """Return existing ruleset and configuration hash"""
    logging.info("Requesting URL: {}".format(get_url_get_rule()))
    ret = {}
    resource = request.urlopen(get_url_get_rule())
    content = resource.read().decode(resource.headers.get_content_charset())
    result = ast.literal_eval(content)
    ret["ruleset"] = result["result"]["ruleset"][""]
    ret["config_hash"] = result["result"]["configuration_hash"]
    logging.info("Ruleset {} has {} rules".format(RULESET_NAME, len(ret["ruleset"])))
    logging.info("Configuration hash: {}".format(ret["config_hash"]))
    return ret


def activate_changes():
    """Same as:
    curl "http://myserver/mysite/check_mk/webapi.py?_secret=myautomationsecret&_username=automation&action=activate_changes"
    \ -d 'request={"sites":["mysite"],"allow_foreign_changes":"1"}'
    """
    logging.info(f"Updating {CHECKMK_SITE}")
    logging.info("Requesting URL: {}".format(get_url_activate_changes()))
    req = {}
    req["mode"] = "specific"
    resposta["sites"] = [CHECKMK_SITE]
    resposta[
        "allow_foreign_changes"
    ] = "1"  # ATTENTION: all changes will be applied (including from other users)
    req["comment"] = "Changes made by automation"
    request_string = "request=" + convert_string_python2(repr(req))
    request_string = parse.quote(request_string, safe='{[]}"=, :')
    req = request.Request(get_url_activate_changes(), request_string.encode())
    resp = request.urlopen(req)
    return resp.read()


def main():
    try:
        if len(sys.argv) < 6:
            print(
                "Usage: update_ruleset.py myhost mymonitor 10.10.10.10 8080 /myapp \nEnvironment vars are expected: CHECKMK_USER, CHECKMK_PASSWORD and CHECKMK_URL"
            )
            sys.exit(1)
        hostname = sys.argv[1]
        monitor = {}
        monitor["name"] = sys.argv[2]
        monitor["url"] = sys.argv[3]
        monitor["port"] = sys.argv[4]
        monitor["uri"] = sys.argv[5]
        ret = get_ruleset_confighash()
        ruleset = ret["ruleset"]
        config_hash = ret["config_hash"]
        new_rule = create_rule(hostname, monitor)
        ruleset.append(new_rule)
        ret_update = update_ruleset(ruleset, config_hash)
        print(ret_update)
        ret_activate_changes = activate_changes()
        print(ret_activate_changes)
    except Exception as e:
        logging.exception(e)


if __name__ == "__main__":
    main()
