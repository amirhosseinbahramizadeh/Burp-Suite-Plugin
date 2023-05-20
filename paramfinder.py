from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Hidden Parameter Discovery | AmiRHbz")

        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        self._analyzeRequest(messageInfo)

    def _analyzeRequest(self, messageInfo):
        request = messageInfo.getRequest()
        parameters = self._helpers.getRequestParameters(request)

        for parameter in parameters:
            name = parameter.getName()
            value = parameter.getValue()

            if parameter.getType() == IParameter.PARAM_COOKIE:
                continue

            if self._isHiddenParameter(name):
                self._reportHiddenParameter(name, value, messageInfo)

    def _isHiddenParameter(self, name):
        # Your hidden parameter detection logic goes here
        return name.startswith("__")

    def _reportHiddenParameter(self, name, value, messageInfo):
        url = messageInfo.getUrl()
        self._callbacks.issueAlert("Hidden parameter discovered: %s=%s in %s" % (name, value, url))