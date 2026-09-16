# -*- coding: utf-8 -*-
"""
HunterAI Burp Suite Jython Extension (Enhanced Bridge)
======================================================
Deep Bi-Directional Integration between Burp Suite and HunterAI:
- Context Menu:
    Right-Click Request
      ├── [HunterAI] Send Request to Brain
      ├── [HunterAI] Send + Queue Scan
      ├── [HunterAI] Send + Plan Attack
      ├── [HunterAI] Add Host to Scope
      └── [HunterAI] Import Confirmed Issues to Target Tab
- Auto Mode:
    - Auto-forward Proxy responses
    - Auto-forward Repeater responses
    - Auto-forward Burp Scanner findings
- UI Tab:
    - Live gateway connection status
    - Ingested request and confirmed vulnerability counter
    - One-click "Import Confirmed Issues into Burp"
"""
from burp import (
    IBurpExtender,
    IContextMenuFactory,
    IHttpListener,
    IScanIssue,
    IScannerListener,
    ITab,
)
import json
import urllib2
from java.awt import BorderLayout, Dimension, FlowLayout, Font, GridLayout
from java.io import ByteArrayInputStream
from java.util import ArrayList
from javax.swing import (
    BorderFactory,
    Box,
    BoxLayout,
    JButton,
    JCheckBox,
    JLabel,
    JMenuItem,
    JPanel,
    JScrollPane,
    JTextArea,
    JTextField,
)

DEFAULT_GATEWAY = "http://127.0.0.1:8085"


class CustomScanIssue(IScanIssue):
    """Burp Suite Scan Issue representation for HunterAI findings"""

    def __init__(self, service, url, name, issue_type, severity, confidence, detail, remediation, messages=None):
        self._service = service
        self._url = url
        self._name = name
        self._type = issue_type
        self._severity = severity
        self._confidence = confidence
        self._detail = detail
        self._remediation = remediation
        self._messages = messages or []

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return self._type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return "Discovered and mathematically verified by HunterAI Evidence Court."

    def getIssueDetail(self):
        return self._detail

    def getRemediationBackground(self):
        return self._remediation

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._messages

    def getHttpService(self):
        return self._service


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener, IScannerListener, ITab):
    """Main HunterAI Extension Entrypoint"""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HunterAI Autonomous Bridge")

        self.gateway_url = DEFAULT_GATEWAY
        self.auto_proxy = True
        self.auto_repeater = True
        self.auto_scanner = True

        self.requests_sent = 0
        self.tasks_queued = 0

        # Register listeners
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerListener(self)

        # Build UI Tab
        self._init_ui()
        callbacks.addSuiteTab(self)

        callbacks.printOutput("[✓] HunterAI Burp Extension Active -> " + self.gateway_url)
        callbacks.printOutput("[✓] Context Menus Registered (Scan, Plan, Scope, Import Issues)")

    def _init_ui(self):
        self._panel = JPanel(BorderLayout(10, 10))
        self._panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))

        # Header
        header = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("🛡️ HunterAI Autonomous Pentest Bridge")
        title.setFont(Font("Arial", Font.BOLD, 18))
        header.add(title)

        # Configuration Panel
        config_panel = JPanel(GridLayout(5, 2, 5, 5))
        config_panel.setBorder(BorderFactory.createTitledBorder("Gateway Settings"))

        config_panel.add(JLabel("HunterAI Gateway URL:"))
        self.url_field = JTextField(self.gateway_url)
        config_panel.add(self.url_field)

        self.cb_proxy = JCheckBox("Auto-forward Proxy responses", self.auto_proxy)
        self.cb_proxy.addActionListener(lambda e: setattr(self, "auto_proxy", self.cb_proxy.isSelected()))
        config_panel.add(self.cb_proxy)

        self.cb_repeater = JCheckBox("Auto-forward Repeater responses", self.auto_repeater)
        self.cb_repeater.addActionListener(lambda e: setattr(self, "auto_repeater", self.cb_repeater.isSelected()))
        config_panel.add(self.cb_repeater)

        self.cb_scanner = JCheckBox("Forward Burp Scanner issues", self.auto_scanner)
        self.cb_scanner.addActionListener(lambda e: setattr(self, "auto_scanner", self.cb_scanner.isSelected()))
        config_panel.add(self.cb_scanner)

        # Actions Panel
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_test = JButton("Test Connection", actionPerformed=lambda e: self._test_connection())
        btn_import = JButton("Import Confirmed Issues into Burp", actionPerformed=lambda e: self._import_issues())
        btn_panel.add(btn_test)
        btn_panel.add(btn_import)

        # Log output
        self.log_area = JTextArea(10, 50)
        self.log_area.setEditable(False)
        scroll = JScrollPane(self.log_area)

        top_container = JPanel()
        top_container.setLayout(BoxLayout(top_container, BoxLayout.Y_AXIS))
        top_container.add(header)
        top_container.add(Box.createRigidArea(Dimension(0, 10)))
        top_container.add(config_panel)
        top_container.add(Box.createRigidArea(Dimension(0, 10)))
        top_container.add(btn_panel)

        self._panel.add(top_container, BorderLayout.NORTH)
        self._panel.add(scroll, BorderLayout.CENTER)

    def getTabCaption(self):
        return "HunterAI"

    def getUiComponent(self):
        return self._panel

    def _log(self, text):
        self.log_area.append(text + "\n")
        self._callbacks.printOutput(text)

    def _get_gateway(self):
        url = self.url_field.getText().strip()
        if url.endswith("/"):
            url = url[:-1]
        return url or DEFAULT_GATEWAY

    def _test_connection(self):
        gw = self._get_gateway()
        try:
            req = urllib2.Request(gw + "/health")
            resp = urllib2.urlopen(req, timeout=2.0)
            data = json.loads(resp.read())
            self._log("[✓] Gateway Connected! Status: " + data.get("status", "ok"))
        except Exception as e:
            self._log("[!] Connection failed to " + gw + ": " + str(e))

    def _import_issues(self):
        gw = self._get_gateway()
        try:
            req = urllib2.Request(gw + "/api/issues/export")
            resp = urllib2.urlopen(req, timeout=3.0)
            data = json.loads(resp.read())
            issues = data.get("issues", [])
            count = 0
            for iss in issues:
                service = self._helpers.buildHttpService(iss.get("host", "localhost"), int(iss.get("port", 80)), iss.get("protocol", "http"))
                url = self._helpers.buildHttpRequest(service, self._helpers.stringToBytes(iss.get("path", "/")))
                burp_issue = CustomScanIssue(
                    service=service,
                    url=self._helpers.analyzeRequest(service, self._helpers.stringToBytes("GET " + iss.get("path", "/") + " HTTP/1.1\r\n\r\n")).getUrl(),
                    name=iss.get("issue_name", "[HunterAI] Confirmed Finding"),
                    issue_type=int(iss.get("issue_type", 0x08000000)),
                    severity=iss.get("severity", "High"),
                    confidence=iss.get("confidence", "Certain"),
                    detail=iss.get("issue_detail", ""),
                    remediation=iss.get("remediation_detail", "")
                )
                self._callbacks.addScanIssue(burp_issue)
                count += 1
            self._log("[✓] Imported " + str(count) + " confirmed HunterAI issues into Burp Target tab!")
        except Exception as e:
            self._log("[!] Failed importing issues: " + str(e))

    # Context Menu Factory
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return None

        menu_items = ArrayList()
        item_send = JMenuItem("[HunterAI] Send Request to Brain", actionPerformed=lambda e: self._send_selected(messages[0]))
        item_scan = JMenuItem("[HunterAI] Send + Queue Scan", actionPerformed=lambda e: self._queue_selected(messages[0], "SCAN"))
        item_plan = JMenuItem("[HunterAI] Send + Plan Attack", actionPerformed=lambda e: self._queue_selected(messages[0], "PLAN"))
        item_scope = JMenuItem("[HunterAI] Add Host to Scope", actionPerformed=lambda e: self._add_scope(messages[0]))
        item_import = JMenuItem("[HunterAI] Import Confirmed Issues", actionPerformed=lambda e: self._import_issues())

        menu_items.add(item_send)
        menu_items.add(item_scan)
        menu_items.add(item_plan)
        menu_items.add(item_scope)
        menu_items.add(item_import)
        return menu_items

    def _send_selected(self, messageInfo):
        self._forward_message(messageInfo, tool="context_menu")

    def _queue_selected(self, messageInfo, action):
        service = messageInfo.getHttpService()
        req_info = self._helpers.analyzeRequest(service, messageInfo.getRequest())
        url_str = str(req_info.getUrl())
        gw = self._get_gateway()
        payload = json.dumps({
            "action": action,
            "target_url": url_str,
            "payload": {
                "method": req_info.getMethod(),
                "headers": list(req_info.getHeaders()),
            }
        })
        try:
            req = urllib2.Request(gw + "/api/tasks", payload, {"Content-Type": "application/json"})
            resp = urllib2.urlopen(req, timeout=2.0)
            self._log("[✓] Queued " + action + " task for " + url_str)
        except Exception as e:
            self._log("[!] Failed to queue task: " + str(e))

    def _add_scope(self, messageInfo):
        service = messageInfo.getHttpService()
        host = service.getHost()
        gw = self._get_gateway()
        payload = json.dumps({"host": host})
        try:
            req = urllib2.Request(gw + "/api/scope", payload, {"Content-Type": "application/json"})
            resp = urllib2.urlopen(req, timeout=2.0)
            self._log("[✓] Host " + host + " added to HunterAI Scope!")
        except Exception as e:
            self._log("[!] Failed to add scope: " + str(e))

    # HTTP Listener (Auto Mode)
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or messageInfo.getResponse() is None:
            return

        is_proxy = toolFlag == self._callbacks.TOOL_PROXY
        is_repeater = toolFlag == self._callbacks.TOOL_REPEATER

        if is_proxy and not self.auto_proxy:
            return
        if is_repeater and not self.auto_repeater:
            return

        tool_name = "proxy" if is_proxy else ("repeater" if is_repeater else "other")
        self._forward_message(messageInfo, tool=tool_name)

    def _forward_message(self, messageInfo, tool="proxy"):
        service = messageInfo.getHttpService()
        req_bytes = messageInfo.getRequest()
        resp_bytes = messageInfo.getResponse()
        gw = self._get_gateway()

        payload = json.dumps({
            "host": service.getHost(),
            "port": service.getPort(),
            "protocol": service.getProtocol(),
            "request": self._helpers.bytesToString(req_bytes),
            "response": self._helpers.bytesToString(resp_bytes) if resp_bytes else "",
            "tool": tool
        })

        try:
            req = urllib2.Request(gw + "/api/traffic", payload, {"Content-Type": "application/json"})
            urllib2.urlopen(req, timeout=1.5)
            self.requests_sent += 1
        except Exception:
            pass  # Non-blocking fail-safe

    # Scanner Listener
    def newScanIssue(self, issue):
        if not self.auto_scanner:
            return
        gw = self._get_gateway()
        payload = json.dumps({
            "name": issue.getIssueName(),
            "type": issue.getIssueType(),
            "severity": issue.getSeverity(),
            "confidence": issue.getConfidence(),
            "url": str(issue.getUrl()),
            "detail": issue.getIssueDetail(),
        })
        try:
            req = urllib2.Request(gw + "/api/issues/burp", payload, {"Content-Type": "application/json"})
            urllib2.urlopen(req, timeout=1.5)
        except Exception:
            pass

    # Execution Facilities (Burp Control & Sensor Layer - BCSL)
    def execute_http_request(self, host, port, protocol, req_str):
        """Executes an HTTP request directly through Burp network facilities"""
        service = self._helpers.buildHttpService(host, int(port), protocol)
        req_bytes = self._helpers.stringToBytes(req_str)
        resp_msg = self._callbacks.makeHttpRequest(service, req_bytes)
        resp_bytes = resp_msg.getResponse() if resp_msg else None
        return self._helpers.bytesToString(resp_bytes) if resp_bytes else ""

    def dispatch_to_repeater(self, host, port, protocol, req_str, tab_caption):
        """Provisions a Repeater tab in Burp Suite UI"""
        use_https = protocol.lower() == "https"
        req_bytes = self._helpers.stringToBytes(req_str)
        self._callbacks.sendToRepeater(host, int(port), use_https, req_bytes, tab_caption)
        self._log("[✓] Dispatched request to Burp Repeater Tab: " + str(tab_caption))
        return True
