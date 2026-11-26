# -*- coding: utf-8 -*-
"""
HunterAI Burp Suite Jython Extension (Enhanced Bridge)
======================================================
Deep Bi-Directional Integration between Burp Suite and HunterAI:
- Non-blocking bounded background outbound queue (`Queue` + daemon worker thread)
  so Burp's proxy/repeater/scanner threads NEVER block on `urllib2.urlopen`.
- Optional Phase 1 local bearer token header (`X-Hunter-Token` & `Authorization: Bearer`).
- Background inbound task poller against `BurpGateway` `/api/tasks` so Python can
  dispatch Repeater tabs or active checks cleanly without blocking proxy traffic.
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
    - Live gateway connection status & optional gateway token input
    - Ingested request, dropped queue events, and inbound task counters
    - One-click "Import Confirmed Issues into Burp"
"""
try:
    from burp import (
        IBurpExtender,
        IContextMenuFactory,
        IExtensionStateListener,
        IHttpListener,
        IScanIssue,
        IScannerListener,
        ITab,
    )
except ImportError:
    class IBurpExtender(object): pass
    class IContextMenuFactory(object): pass
    class IExtensionStateListener(object): pass
    class IHttpListener(object): pass
    class IScanIssue(object): pass
    class IScannerListener(object): pass
    class ITab(object): pass

import json
import os
import threading
import time

try:
    import Queue as queue_mod
except ImportError:
    import queue as queue_mod

try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

try:
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
    SWING_AVAILABLE = True
except ImportError:
    SWING_AVAILABLE = False

DEFAULT_GATEWAY = "http://127.0.0.1:8085"
DEFAULT_MAX_QUEUE_SIZE = 256
DEFAULT_POLL_INTERVAL_SEC = 2.0


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


class BurpExtender(
    IBurpExtender,
    IContextMenuFactory,
    IExtensionStateListener,
    IHttpListener,
    IScannerListener,
    ITab,
):
    """Main HunterAI Extension Entrypoint"""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HunterAI Autonomous Bridge")

        self.gateway_url = os.environ.get("HUNTER_BURP_GATEWAY_URL", DEFAULT_GATEWAY).strip() or DEFAULT_GATEWAY
        self.api_token = (
            os.environ.get("HUNTER_BURP_GATEWAY_TOKEN", "").strip()
            or os.environ.get("HUNTER_API_TOKEN", "").strip()
        )
        self.auto_proxy = True
        self.auto_repeater = True
        self.auto_scanner = True
        self.poll_tasks_enabled = True
        self.max_queue_size = DEFAULT_MAX_QUEUE_SIZE
        self.poll_interval_sec = DEFAULT_POLL_INTERVAL_SEC

        self.requests_sent = 0
        self.dropped_events = 0
        self.tasks_queued = 0
        self.inbound_tasks_executed = 0
        self._dispatched_task_ids = set()
        self._dispatched_lock = threading.Lock()

        # Bounded background outbound queue & stop event
        self._stop_event = threading.Event()
        self._outbound_queue = queue_mod.Queue(maxsize=self.max_queue_size)
        self._outbound_thread = None
        self._task_poller_thread = None

        # Register listeners
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerListener(self)
        if hasattr(callbacks, "registerExtensionStateListener"):
            callbacks.registerExtensionStateListener(self)

        # Build UI Tab when Swing is available
        self.url_field = None
        self.token_field = None
        self.log_area = None
        self._panel = None
        if SWING_AVAILABLE:
            self._init_ui()
            callbacks.addSuiteTab(self)

        # Start non-blocking background workers
        self._start_background_workers()

        callbacks.printOutput("[✓] HunterAI Burp Extension Active -> " + self.gateway_url)
        callbacks.printOutput("[✓] Outbound queue worker + Inbound /api/tasks poller running (daemon threads)")
        callbacks.printOutput("[✓] Context Menus Registered (Scan, Plan, Scope, Import Issues)")

    def _start_background_workers(self):
        self._stop_event.clear()
        if self._outbound_thread is None or not self._outbound_thread.is_alive():
            self._outbound_thread = threading.Thread(
                target=self._outbound_worker_loop,
                name="HunterAI-OutboundForwarder",
            )
            self._outbound_thread.setDaemon(True)
            self._outbound_thread.start()

        if self._task_poller_thread is None or not self._task_poller_thread.is_alive():
            self._task_poller_thread = threading.Thread(
                target=self._task_poller_loop,
                name="HunterAI-InboundTaskPoller",
            )
            self._task_poller_thread.setDaemon(True)
            self._task_poller_thread.start()

    def extensionUnloaded(self):
        """Cleanly terminate background daemon workers when Burp unloads the extension."""
        self.stop()

    def stop(self):
        self._stop_event.set()
        # Wake outbound worker if waiting on queue
        try:
            self._outbound_queue.put_nowait(None)
        except Exception:
            pass

    def _init_ui(self):
        self._panel = JPanel(BorderLayout(10, 10))
        self._panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))

        # Header
        header = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("🛡️ HunterAI Autonomous Pentest Bridge")
        title.setFont(Font("Arial", Font.BOLD, 18))
        header.add(title)

        # Configuration Panel
        config_panel = JPanel(GridLayout(6, 2, 5, 5))
        config_panel.setBorder(BorderFactory.createTitledBorder("Gateway Settings"))

        config_panel.add(JLabel("HunterAI Gateway URL:"))
        self.url_field = JTextField(self.gateway_url)
        config_panel.add(self.url_field)

        config_panel.add(JLabel("X-Hunter-Token (optional):"))
        self.token_field = JTextField(self.api_token)
        config_panel.add(self.token_field)

        self.cb_proxy = JCheckBox("Auto-forward Proxy responses", self.auto_proxy)
        self.cb_proxy.addActionListener(lambda e: setattr(self, "auto_proxy", self.cb_proxy.isSelected()))
        config_panel.add(self.cb_proxy)

        self.cb_repeater = JCheckBox("Auto-forward Repeater responses", self.auto_repeater)
        self.cb_repeater.addActionListener(lambda e: setattr(self, "auto_repeater", self.cb_repeater.isSelected()))
        config_panel.add(self.cb_repeater)

        self.cb_scanner = JCheckBox("Forward Burp Scanner issues", self.auto_scanner)
        self.cb_scanner.addActionListener(lambda e: setattr(self, "auto_scanner", self.cb_scanner.isSelected()))
        config_panel.add(self.cb_scanner)

        self.cb_poller = JCheckBox("Poll Gateway /api/tasks", self.poll_tasks_enabled)
        self.cb_poller.addActionListener(lambda e: setattr(self, "poll_tasks_enabled", self.cb_poller.isSelected()))
        config_panel.add(self.cb_poller)

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
        if self.log_area is not None:
            try:
                self.log_area.append(text + "\n")
            except Exception:
                pass
        if getattr(self, "_callbacks", None) is not None:
            try:
                self._callbacks.printOutput(text)
            except Exception:
                pass

    def _get_gateway(self):
        url = self.gateway_url
        if self.url_field is not None:
            try:
                url = self.url_field.getText().strip()
            except Exception:
                pass
        if url.endswith("/"):
            url = url[:-1]
        return url or DEFAULT_GATEWAY

    def _get_token(self):
        token = self.api_token or ""
        if self.token_field is not None:
            try:
                field_val = self.token_field.getText().strip()
                if field_val:
                    token = field_val
            except Exception:
                pass
        return token.strip()

    def _build_headers(self, extra=None):
        headers = {}
        if extra:
            for k, v in extra.items():
                headers[k] = v
        token = self._get_token()
        if token:
            headers["X-Hunter-Token"] = token
            headers["Authorization"] = "Bearer " + token
        return headers

    def _encode_body(self, payload_dict):
        raw = json.dumps(payload_dict)
        # Python 3 urllib.request expects bytes; Jython 2.7 accepts str
        if not isinstance(raw, bytes):
            raw = raw.encode("utf-8")
        return raw

    def _http_post(self, path, payload_dict, timeout=2.0):
        gw = self._get_gateway()
        headers = self._build_headers({"Content-Type": "application/json"})
        body = self._encode_body(payload_dict)
        req = urllib2.Request(gw + path, body, headers)
        return urllib2.urlopen(req, timeout=timeout)

    def _http_get(self, path, timeout=2.0):
        gw = self._get_gateway()
        headers = self._build_headers()
        req = urllib2.Request(gw + path, headers=headers)
        return urllib2.urlopen(req, timeout=timeout)

    def _enqueue_outbound(self, path, payload_dict, kind="traffic"):
        """Non-blocking enqueue onto the bounded background worker queue."""
        try:
            self._outbound_queue.put_nowait((path, payload_dict, kind))
            return True
        except queue_mod.Full:
            self.dropped_events += 1
            return False

    def _deliver_outbound_item(self, item):
        if item is None:
            return False
        path, payload_dict, kind = item
        try:
            self._http_post(path, payload_dict, timeout=2.0)
            if kind == "traffic":
                self.requests_sent += 1
            elif kind == "task":
                self.tasks_queued += 1
            return True
        except Exception:
            return False

    def process_one_outbound(self, timeout=0.1):
        """Process a single queued outbound event (useful for deterministic tests)."""
        try:
            item = self._outbound_queue.get(timeout=timeout)
        except queue_mod.Empty:
            return False
        try:
            return self._deliver_outbound_item(item)
        finally:
            try:
                self._outbound_queue.task_done()
            except Exception:
                pass

    def _outbound_worker_loop(self):
        """Dedicated background daemon worker: executes all outbound HTTP calls off Burp's proxy thread."""
        while not self._stop_event.is_set():
            try:
                item = self._outbound_queue.get(timeout=0.5)
            except queue_mod.Empty:
                continue
            try:
                if item is None:
                    break
                self._deliver_outbound_item(item)
            finally:
                try:
                    self._outbound_queue.task_done()
                except Exception:
                    pass

    def _task_poller_loop(self):
        """Background daemon poller reading inbound tasks from BurpGateway /api/tasks."""
        while not self._stop_event.is_set():
            if self.poll_tasks_enabled:
                try:
                    self.poll_tasks_once()
                except Exception:
                    pass
            self._stop_event.wait(self.poll_interval_sec)

    def poll_tasks_once(self):
        """Poll GET /api/tasks once and execute any pending Burp-targeted Repeater/active check tasks."""
        resp = self._http_get("/api/tasks", timeout=2.0)
        raw = resp.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        data = json.loads(raw or "{}")
        tasks = data.get("tasks", []) if isinstance(data, dict) else []
        executed = []

        for task in tasks:
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("task_id") or "")
            status = str(task.get("status") or "").upper()
            if not task_id or status not in ("QUEUED", "PENDING"):
                continue

            action = str(task.get("action") or "").upper()
            payload = task.get("payload") or {}
            burp_action = str(payload.get("burp_action") or "").upper()
            wants_burp = bool(payload.get("dispatch_to_burp")) or burp_action in (
                "REPEATER", "SEND_REPEATER", "PROBE", "ACTIVE_CHECK", "HTTP_REQUEST",
            ) or action in ("REPEATER", "PROBE")
            if not wants_burp:
                continue

            with self._dispatched_lock:
                if task_id in self._dispatched_task_ids:
                    continue
                self._dispatched_task_ids.add(task_id)

            outcome = self._execute_inbound_task(task, burp_action or action)
            executed.append(outcome)
            self.inbound_tasks_executed += 1
            try:
                self._http_post(
                    "/api/tasks/" + task_id + "/complete",
                    outcome,
                    timeout=2.0,
                )
            except Exception:
                pass
        return executed

    def _execute_inbound_task(self, task, effective_action):
        task_id = str(task.get("task_id") or "")
        target_url = str(task.get("target_url") or "")
        payload = task.get("payload") or {}
        parsed = urlparse(target_url) if target_url else None
        host = str(payload.get("host") or (parsed.hostname if parsed else "") or "127.0.0.1")
        protocol = str(payload.get("protocol") or (parsed.scheme if parsed else "") or "http").lower()
        default_port = 443 if protocol == "https" else 80
        port = int(payload.get("port") or (parsed.port if parsed else None) or default_port)
        raw_req = payload.get("raw_request")
        if not raw_req:
            method = str(payload.get("method") or "GET").upper()
            path = (parsed.path or "/") if parsed else "/"
            if parsed and parsed.query:
                path = path + "?" + parsed.query
            raw_req = method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

        try:
            if effective_action in ("REPEATER", "SEND_REPEATER"):
                tab_name = str(payload.get("tab_name") or ("HunterAI:" + task_id[:8]))
                self.dispatch_to_repeater(host, port, protocol, raw_req, tab_name)
                return {
                    "task_id": task_id,
                    "status": "COMPLETED",
                    "result": {"dispatched": "repeater", "tab_name": tab_name, "host": host, "port": port},
                }
            resp_text = self.execute_http_request(host, port, protocol, raw_req)
            return {
                "task_id": task_id,
                "status": "COMPLETED",
                "result": {
                    "dispatched": "active_check",
                    "host": host,
                    "port": port,
                    "response_length": len(resp_text or ""),
                    "response_preview": (resp_text or "")[:1000],
                },
            }
        except Exception as e:
            return {
                "task_id": task_id,
                "status": "FAILED",
                "error": str(e),
            }

    def _test_connection(self):
        try:
            resp = self._http_get("/health", timeout=2.0)
            raw = resp.read()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            data = json.loads(raw)
            self._log("[✓] Gateway Connected! Status: " + data.get("status", "ok"))
        except Exception as e:
            self._log("[!] Connection failed to " + self._get_gateway() + ": " + str(e))

    def _import_issues(self):
        try:
            resp = self._http_get("/api/issues/export", timeout=3.0)
            raw = resp.read()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            data = json.loads(raw)
            issues = data.get("issues", [])
            count = 0
            for iss in issues:
                service = self._helpers.buildHttpService(
                    iss.get("host", "localhost"),
                    int(iss.get("port", 80)),
                    iss.get("protocol", "http"),
                )
                burp_issue = CustomScanIssue(
                    service=service,
                    url=self._helpers.analyzeRequest(
                        service,
                        self._helpers.stringToBytes("GET " + iss.get("path", "/") + " HTTP/1.1\r\n\r\n"),
                    ).getUrl(),
                    name=iss.get("issue_name", "[HunterAI] Confirmed Finding"),
                    issue_type=int(iss.get("issue_type", 0x08000000)),
                    severity=iss.get("severity", "High"),
                    confidence=iss.get("confidence", "Certain"),
                    detail=iss.get("issue_detail", ""),
                    remediation=iss.get("remediation_detail", ""),
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
        payload = {
            "action": action,
            "target_url": url_str,
            "payload": {
                "method": req_info.getMethod(),
                "headers": list(req_info.getHeaders()),
            },
        }
        if self._enqueue_outbound("/api/tasks", payload, kind="task"):
            self._log("[✓] Queued " + action + " task for " + url_str)
        else:
            self._log("[!] Outbound queue full; dropped task for " + url_str)

    def _add_scope(self, messageInfo):
        service = messageInfo.getHttpService()
        host = service.getHost()
        if self._enqueue_outbound("/api/scope", {"host": host}, kind="scope"):
            self._log("[✓] Queued host " + host + " for HunterAI Scope!")
        else:
            self._log("[!] Outbound queue full; failed to queue scope update for " + host)

    # HTTP Listener (Auto Mode) — strictly non-blocking on Burp proxy thread
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

        payload = {
            "host": service.getHost(),
            "port": service.getPort(),
            "protocol": service.getProtocol(),
            "request": self._helpers.bytesToString(req_bytes),
            "response": self._helpers.bytesToString(resp_bytes) if resp_bytes else "",
            "tool": tool,
        }
        # Never call urllib2.urlopen on Burp's proxy thread: hand off to bounded worker queue.
        self._enqueue_outbound("/api/traffic", payload, kind="traffic")

    # Scanner Listener — non-blocking handoff to bounded worker queue
    def newScanIssue(self, issue):
        if not self.auto_scanner:
            return
        payload = {
            "name": issue.getIssueName(),
            "type": issue.getIssueType(),
            "severity": issue.getSeverity(),
            "confidence": issue.getConfidence(),
            "url": str(issue.getUrl()),
            "detail": issue.getIssueDetail(),
            "verified_by_burp": True,
        }
        self._enqueue_outbound("/api/issues/burp", payload, kind="issue")

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
