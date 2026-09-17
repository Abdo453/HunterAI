# -*- coding: utf-8 -*-
"""
HunterAI Burp Suite Jython Extension
Forwards live Burp HTTP traffic to HunterAI BurpAgent (http://127.0.0.1:8085/api/traffic)
"""
try:
    from burp import IBurpExtender, IHttpListener
except ImportError:
    class IBurpExtender(object): pass
    class IHttpListener(object): pass

import json
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

AGENT_ENDPOINT = "http://127.0.0.1:8085/api/traffic"

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HunterAI Burp Forwarder (Python)")
        callbacks.registerHttpListener(self)
        print("[+] HunterAI Burp Python Forwarder Active -> " + AGENT_ENDPOINT)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest and messageInfo.getResponse():
            try:
                service = messageInfo.getHttpService()
                req_bytes = messageInfo.getRequest()
                resp_bytes = messageInfo.getResponse()

                payload = {
                    "host": service.getHost(),
                    "port": service.getPort(),
                    "protocol": service.getProtocol(),
                    "request": self._helpers.bytesToString(req_bytes),
                    "response": self._helpers.bytesToString(resp_bytes)
                }

                req = urllib2.Request(AGENT_ENDPOINT, json.dumps(payload), {'Content-Type': 'application/json'})
                urllib2.urlopen(req, timeout=1.5)
            except Exception:
                pass # Fail-safe, non-blocking
