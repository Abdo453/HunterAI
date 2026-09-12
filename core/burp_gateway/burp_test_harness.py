"""
HunterAI Burp Extender Simulation & Test Harness
================================================
Provides a complete Python 3 simulation environment for Burp Suite Extender APIs:
- Mocks burp interfaces (IBurpExtender, IContextMenuFactory, IHttpListener, ITab, IScanIssue)
- Mocks Java Swing / AWT UI components
- Mocks urllib2 bridge for Python 3 runtime
- Enables real runtime execution and verification of hunter_burp_extension.py without JVM
"""
from __future__ import annotations

import ast
import importlib
import io
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# ── 1. JAVA RUNTIME & SWING MOCKS ─────────────────────────────────────────────

class MockJavaComponent:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.children: List[Any] = []
        self._action_listener = kwargs.get("actionPerformed")

    def add(self, child, *layout_args):
        self.children.append(child)
        return child

    def setBorder(self, border):
        self.border = border

    def setFont(self, font):
        self.font = font

    def setLayout(self, layout):
        self.layout = layout

    def setEditable(self, editable):
        self.editable = editable

    def append(self, text):
        if not hasattr(self, "_content"):
            self._content = ""
        self._content += text

    def getText(self):
        if hasattr(self, "_content"):
            return self._content
        return getattr(self, "_text", "")

    def setText(self, text):
        self._text = text

    def isSelected(self):
        return getattr(self, "_selected", True)

    def setSelected(self, val):
        self._selected = val

    def addActionListener(self, fn):
        self._action_listener = fn

    def fire_action(self):
        if self._action_listener:
            class DummyEvent:
                pass
            return self._action_listener(DummyEvent())


class MockJPanel(MockJavaComponent):
    pass


class MockJLabel(MockJavaComponent):
    def __init__(self, text="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._text = text


class MockJTextField(MockJavaComponent):
    def __init__(self, text="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._text = text


class MockJCheckBox(MockJavaComponent):
    def __init__(self, text="", selected=True, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._text = text
        self._selected = selected


class MockJButton(MockJavaComponent):
    def __init__(self, text="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._text = text


class MockJTextArea(MockJavaComponent):
    def __init__(self, rows=10, cols=50, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._content = ""


class MockJScrollPane(MockJavaComponent):
    def __init__(self, view=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.view = view


class MockJMenuItem(MockJavaComponent):
    def __init__(self, text="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._text = text


class MockBorderFactory:
    @staticmethod
    def createEmptyBorder(*args):
        return ("EmptyBorder", args)

    @staticmethod
    def createTitledBorder(title):
        return ("TitledBorder", title)


class MockBox:
    @staticmethod
    def createRigidArea(dim):
        return ("RigidArea", dim)


class MockDimension:
    def __init__(self, width, height):
        self.width = width
        self.height = height


class MockFont:
    BOLD = 1
    PLAIN = 0

    def __init__(self, name, style, size):
        self.name = name
        self.style = style
        self.size = size


class MockArrayList(list):
    def add(self, item):
        self.append(item)


# ── 2. BURP INTERFACES MOCK ───────────────────────────────────────────────────

class IBurpExtender:
    def registerExtenderCallbacks(self, callbacks):
        pass


class IContextMenuFactory:
    def createMenuItems(self, invocation):
        return None


class IHttpListener:
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass


class IScannerListener:
    def newScanIssue(self, issue):
        pass


class ITab:
    def getTabCaption(self):
        return ""

    def getUiComponent(self):
        return None


class IScanIssue:
    def getUrl(self):
        pass

    def getIssueName(self):
        pass

    def getIssueType(self):
        pass

    def getSeverity(self):
        pass

    def getConfidence(self):
        pass

    def getIssueDetail(self):
        pass

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        pass

    def getHttpService(self):
        pass


# ── 3. BURP RUNTIME ENVIRONMENT HARNESS ───────────────────────────────────────

class MockHttpService:
    def __init__(self, host="portal.target.local", port=443, protocol="https"):
        self._host = host
        self._port = port
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol


class MockHttpRequestResponse:
    def __init__(
        self,
        request: bytes,
        response: Optional[bytes] = None,
        service: Optional[MockHttpService] = None,
    ):
        self._request = request
        self._response = response
        self._service = service or MockHttpService()

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def getHttpService(self):
        return self._service


class MockRequestInfo:
    def __init__(self, service: MockHttpService, request_bytes: bytes):
        self._service = service
        self._request_str = request_bytes.decode("utf-8", errors="replace")
        lines = self._request_str.splitlines()
        first_line = lines[0] if lines else "GET / HTTP/1.1"
        parts = first_line.split()
        self._method = parts[0] if len(parts) > 0 else "GET"
        self._path = parts[1] if len(parts) > 1 else "/"
        self._headers = [l for l in lines[1:] if ":" in l]
        port_str = f":{service.getPort()}" if service.getPort() not in (80, 443) else ""
        self._url = f"{service.getProtocol()}://{service.getHost()}{port_str}{self._path}"

    def getMethod(self):
        return self._method

    def getUrl(self):
        return self._url

    def getHeaders(self):
        return self._headers


class MockExtensionHelpers:
    def stringToBytes(self, s: str) -> bytes:
        return s.encode("utf-8") if isinstance(s, str) else s

    def bytesToString(self, b: bytes) -> str:
        return b.decode("utf-8", errors="replace") if isinstance(b, bytes) else str(b)

    def buildHttpService(self, host: str, port: int, protocol: str) -> MockHttpService:
        return MockHttpService(host, port, protocol)

    def buildHttpRequest(self, service: MockHttpService, path_bytes: bytes) -> bytes:
        path = self.bytesToString(path_bytes)
        return f"GET {path} HTTP/1.1\r\nHost: {service.getHost()}\r\n\r\n".encode("utf-8")

    def analyzeRequest(self, service: MockHttpService, req_bytes: bytes) -> MockRequestInfo:
        return MockRequestInfo(service, req_bytes)


class MockContextMenuInvocation:
    def __init__(self, messages: List[MockHttpRequestResponse]):
        self._messages = messages

    def getSelectedMessages(self) -> List[MockHttpRequestResponse]:
        return self._messages


class MockBurpExtenderCallbacks:
    TOOL_PROXY = 4
    TOOL_REPEATER = 64
    TOOL_SCANNER = 16

    def __init__(self):
        self.extension_name = ""
        self.helpers = MockExtensionHelpers()
        self.context_menu_factories: List[Any] = []
        self.http_listeners: List[Any] = []
        self.scanner_listeners: List[Any] = []
        self.tabs: List[ITab] = []
        self.scan_issues: List[IScanIssue] = []
        self.stdout_log: List[str] = []
        self.stderr_log: List[str] = []

    def setExtensionName(self, name: str):
        self.extension_name = name

    def getHelpers(self) -> MockExtensionHelpers:
        return self.helpers

    def registerContextMenuFactory(self, factory):
        self.context_menu_factories.append(factory)

    def registerHttpListener(self, listener):
        self.http_listeners.append(listener)

    def registerScannerListener(self, listener):
        self.scanner_listeners.append(listener)

    def addSuiteTab(self, tab: ITab):
        self.tabs.append(tab)

    def addScanIssue(self, issue: IScanIssue):
        self.scan_issues.append(issue)

    def printOutput(self, message: str):
        self.stdout_log.append(str(message))

    def printError(self, message: str):
        self.stderr_log.append(str(message))


# ── 4. PYTHON 3 URLLIB2 COMPATIBILITY SHIM ────────────────────────────────────

class Urllib2Shim:
    """Provides urllib2 interface compatible with Jython script in Python 3"""
    class Request:
        def __init__(self, url, data=None, headers=None):
            self.url = url
            self.data = data.encode("utf-8") if isinstance(data, str) else data
            self.headers = headers or {}
            self._py_req = urllib.request.Request(self.url, data=self.data, headers=self.headers)

    @staticmethod
    def urlopen(req, timeout=2.0):
        if isinstance(req, Urllib2Shim.Request):
            py_req = req._py_req
        elif isinstance(req, str):
            py_req = urllib.request.Request(req)
        else:
            py_req = req

        resp = urllib.request.urlopen(py_req, timeout=timeout)
        return resp


def setup_burp_environment():
    """Injects mock Java, Swing, and Burp modules into sys.modules"""
    # 1. Burp module
    burp_mod = type(sys)("burp")
    burp_mod.IBurpExtender = IBurpExtender
    burp_mod.IContextMenuFactory = IContextMenuFactory
    burp_mod.IHttpListener = IHttpListener
    burp_mod.IScanIssue = IScanIssue
    burp_mod.IScannerListener = IScannerListener
    burp_mod.ITab = ITab
    sys.modules["burp"] = burp_mod

    # 2. javax.swing module
    swing_mod = type(sys)("javax.swing")
    swing_mod.BorderFactory = MockBorderFactory
    swing_mod.Box = MockBox
    class MockBoxLayout:
        Y_AXIS = 1
        X_AXIS = 0
        def __init__(self, *args, **kwargs):
            pass
    swing_mod.BoxLayout = MockBoxLayout
    swing_mod.JButton = MockJButton
    swing_mod.JCheckBox = MockJCheckBox
    swing_mod.JLabel = MockJLabel
    swing_mod.JMenuItem = MockJMenuItem
    swing_mod.JPanel = MockJPanel
    swing_mod.JScrollPane = MockJScrollPane
    swing_mod.JTextArea = MockJTextArea
    swing_mod.JTextField = MockJTextField
    sys.modules["javax.swing"] = swing_mod

    # 3. java.awt module
    awt_mod = type(sys)("java.awt")
    class MockBorderLayout:
        NORTH = "North"
        CENTER = "Center"
        SOUTH = "South"
        def __init__(self, *args, **kwargs):
            pass
    class MockFlowLayout:
        LEFT = 0
        CENTER = 1
        RIGHT = 2
        def __init__(self, *args, **kwargs):
            pass
    class MockGridLayout:
        def __init__(self, *args, **kwargs):
            pass
    awt_mod.BorderLayout = MockBorderLayout
    awt_mod.Dimension = MockDimension
    awt_mod.FlowLayout = MockFlowLayout
    awt_mod.Font = MockFont
    awt_mod.GridLayout = MockGridLayout
    sys.modules["java.awt"] = awt_mod

    # 4. java.util module
    util_mod = type(sys)("java.util")
    util_mod.ArrayList = MockArrayList
    sys.modules["java.util"] = util_mod

    # 5. java.io module
    io_mod = type(sys)("java.io")
    io_mod.ByteArrayInputStream = io.BytesIO
    sys.modules["java.io"] = io_mod

    # 6. urllib2 module for Python 3
    sys.modules["urllib2"] = Urllib2Shim


class BurpTestHarness:
    """
    Complete Burp Test Harness loading and executing the real Jython extension in Python 3.
    """

    def __init__(self, extension_path: Optional[Path] = None):
        setup_burp_environment()
        if extension_path is None:
            root = Path(__file__).resolve().parent.parent.parent
            extension_path = root / "agents" / "burp_agent" / "integrations" / "burp_extension" / "hunter_burp_extension.py"

        self.extension_path = extension_path
        self.callbacks = MockBurpExtenderCallbacks()
        self.extender: Any = None
        self._load_extension()

    def _load_extension(self):
        """Loads and instantiates BurpExtender from the real Python source"""
        code = self.extension_path.read_text(encoding="utf-8")
        namespace: Dict[str, Any] = {}
        exec(code, namespace)
        extender_cls = namespace.get("BurpExtender")
        if not extender_cls:
            raise RuntimeError("BurpExtender class not found in extension source.")
        self.extender = extender_cls()
        self.extender.registerExtenderCallbacks(self.callbacks)

    def get_suite_tab(self) -> Optional[ITab]:
        return self.callbacks.tabs[0] if self.callbacks.tabs else None

    def send_proxy_message(
        self,
        request_str: str,
        response_str: str,
        host: str = "portal.target.local",
        port: int = 443,
        protocol: str = "https",
    ):
        service = MockHttpService(host, port, protocol)
        req_resp = MockHttpRequestResponse(
            request=request_str.encode("utf-8"),
            response=response_str.encode("utf-8"),
            service=service,
        )
        self.extender.processHttpMessage(
            self.callbacks.TOOL_PROXY,
            False,  # messageIsRequest=False (response ready)
            req_resp,
        )
        return req_resp

    def trigger_context_menu(
        self,
        action_name: str,
        request_str: str,
        host: str = "portal.target.local",
    ) -> bool:
        service = MockHttpService(host, 443, "https")
        req_resp = MockHttpRequestResponse(
            request=request_str.encode("utf-8"),
            response=None,
            service=service,
        )
        inv = MockContextMenuInvocation([req_resp])
        menu_items = self.extender.createMenuItems(inv)
        if not menu_items:
            return False

        for item in menu_items:
            if action_name.lower() in item.getText().lower():
                item.fire_action()
                return True
        return False
