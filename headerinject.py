from burp import IBurpExtender, IHttpListener, IProxyListener, IScannerListener, ITab

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("HTTP Header Injection | AmiRHbz")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerListener(self)
        self._callbacks.addSuiteTab(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        if messageIsRequest:
            request = currentRequest.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(request)
            headers = analyzedRequest.getHeaders()
            for i in range(len(headers)):
                header = headers[i]
                if header.startswith("Host:"):
                    continue
                payload = ["X-Injection: " + header + "test\r\n",
                           "X-Real-IP: " + header + "test\r\n",
                           "X-Forwarded-Server: " + header + "test\r\n",
                           "X-Forwarded-Proto: " + header + "test\r\n",
                           "X-Forwarded-Host: " + header + "test\r\n",
                           "X-Forwarded-For: " + header + "test\r\n",
                           "Accept-Language: en-US,en;q= " + header + "test\r\n"
                           ]
                newHeaders = list(headers)
                newHeaders.insert(i + 1, payload)
                newRequest = self._helpers.buildHttpMessage(newHeaders, request[analyzedRequest.getBodyOffset():])
                currentRequest.setRequest(newRequest)
                break
            
    def getTabCaption(self):
        return "HTTP Header Injection"
    
    def getUiComponent(self):
        return None