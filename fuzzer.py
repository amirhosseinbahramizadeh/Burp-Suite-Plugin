from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IScannerCheck
from burp import IParameter
from java.io import PrintWriter
from java.util import List, ArrayList

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IIntruderPayloadGeneratorFactory, IScannerInsertionPointProvider, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Web Application Fuzzer | AmiRHbz")

        callbacks.registerContextMenuFactory(self)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.registerScannerInsertionPointProvider(self)
        callbacks.registerScannerCheck(self)

    def createMenuItems(self, invocation):
        menuList = ArrayList()
        menuList.add(CustomMenuItem("Fuzz with Intruder", FuzzerMenu(invocation)))

        return menuList

    def getTabCaption(self):
        return "Web Application Fuzzer"

    def getUiComponent(self):
        return self._tab

    def createNewInstance(self, attack):
        return FuzzerPayloadGenerator(self)

    def getInsertionPoints(self, baseRequestResponse):
        insertionPoints = []

        request = baseRequestResponse.getRequest()
        parameters = self._helpers.getRequestParameters(request)

        for parameter in parameters:
            name = parameter.getName()
            insertionPoints.append(FuzzerInsertionPoint(baseRequestResponse, parameter))

        return insertionPoints

    def doPassiveScan(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()
        parameters = self._helpers.getRequestParameters(request)

        for parameter in parameters:
            name = parameter.getName()

            if self._isFuzzableParameter(name):
                url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                self._callbacks.addScanIssue(FuzzerScanIssue(url, name, parameter))

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        payload = "FUZZ"
        payloadBytes = self._helpers.stringToBytes(payload)

        for i in range(256):
            payloadBytes[0] = i
            testRequest = self._helpers.buildHttpRequest(insertionPoint.getBaseRequestResponse().getHttpService(), insertionPoint.buildRequest(payloadBytes))
            testRequestResponse = self._callbacks.makeHttpRequest(insertionPoint.getBaseRequestResponse().getHttpService(), testRequest)

            if insertionPoint.getBaseRequestResponse().getResponse() != testRequestResponse:
                return [FuzzerScanIssue(self._helpers.analyzeRequest(baseRequestResponse).getUrl(), insertionPoint.getParameter().getName(), insertionPoint.getParameter(), payload)]

        return None