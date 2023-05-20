from burp import IBurpExtender
from burp import IHttpListener
import re

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Endpoint Extractor | AmiRHbz")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            analyzedResponse = self._helpers.analyzeResponse(response)
            headers = analyzedResponse.getHeaders()
            body = response[analyzedResponse.getBodyOffset():].tostring()
            if "Content-Type: application/javascript" in headers:
                endpoints = re.findall(r'\b(?:https?://|www\.)\S+\b', body)
                for endpoint in endpoints:
                    print(endpoint)