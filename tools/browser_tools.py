"""Browser Controller — Multi-Browser (Chrome, Chromium, Firefox / Kali, Edge) + BurpSuite Proxy + DOM Automation"""
import os
import time
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Any, List, Dict

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.edge.options import Options as EdgeOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM = True
except ImportError:
    SELENIUM = False
    By = Any = None
    ChromeOptions = FirefoxOptions = EdgeOptions = None


class BrowserController:
    """
    تحكم شامل في المتصفحات (يدعم كالي لينكس وويندوز):
    - 🦊 Firefox / Firefox-ESR (المتصفح الافتراضي في كالي لينكس)
    - 🌐 Google Chrome & Chromium
    - 🌊 Microsoft Edge
    - توجيه الترافيك لـ Burp Suite (127.0.0.1:8080)
    - استخراج الـ DOM والنماذج والأزرار والتقاط الصور
    """

    def __init__(self, headless: bool = True, proxy: Optional[str] = None,
                 screenshots_dir: str = "data/screenshots"):
        self.headless = headless
        self.proxy = proxy
        self.ss_dir = Path(screenshots_dir)
        self.ss_dir.mkdir(parents=True, exist_ok=True)
        self.driver = None
        self.active_browser = None

    @staticmethod
    def detect_available_browsers() -> Dict[str, bool]:
        """فحص المتصفحات المثبتة على النظام (كالي لينكس أو ويندوز)"""
        return {
            "firefox": any(shutil.which(x) for x in ["firefox", "firefox-esr", "geckodriver"]),
            "chromium": any(shutil.which(x) for x in ["chromium", "chromium-browser"]),
            "chrome": any(shutil.which(x) for x in ["google-chrome", "chrome", "google-chrome-stable"]),
            "edge": any(shutil.which(x) for x in ["msedge", "edge", "microsoft-edge"]),
        }

    def start(self, visible: bool = False, preferred_browser: str = "auto") -> bool:
        """
        تشغيل المتصفح مع التبديل التلقائي (Auto-Fallback):
        يجرب Chrome/Chromium ثم Firefox (كالي) ثم Edge
        """
        if not SELENIUM:
            print("[Browser] Selenium library is not installed.")
            return False

        browsers_to_try = []
        env_pref = os.getenv("PREFERRED_BROWSER", "").lower()
        effective_pref = env_pref or preferred_browser.lower()

        if effective_pref in ("chrome", "chromium"):
            browsers_to_try = ["chrome", "chromium", "firefox", "edge"]
        else:
            # Default to Firefox first (primary on Kali Linux / Firefox-ESR)
            browsers_to_try = ["firefox", "chromium", "chrome", "edge"]

        for b in browsers_to_try:
            success = False
            if b == "firefox":
                success = self._start_firefox(visible=visible)
            elif b in ("chrome", "chromium"):
                success = self._start_chrome(visible=visible)
            elif b == "edge":
                success = self._start_edge(visible=visible)

            if success:
                self.active_browser = b
                print(f"[Browser] Started {b.upper()} successfully (Headless={not visible and self.headless}, Proxy={self.proxy})")
                return True

        print("[Browser] Failed to launch any supported browser (Chrome, Chromium, Firefox, Edge).")
        return False

    def _start_chrome(self, visible: bool = False) -> bool:
        try:
            opts = ChromeOptions()
            if not visible and self.headless:
                opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--window-size=1920,1080")
            opts.add_argument("--ignore-certificate-errors")
            opts.add_argument("--ignore-ssl-errors=yes")
            opts.add_argument("--allow-insecure-localhost")

            # مسارات كالي وويندوز
            for bin_name in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"]:
                loc = shutil.which(bin_name)
                if loc:
                    opts.binary_location = loc
                    break

            if self.proxy:
                opts.add_argument(f"--proxy-server=http://{self.proxy}")

            # Try direct or with chromedriver binary
            driver_path = shutil.which("chromedriver") or shutil.which("chromium-driver") or "/usr/bin/chromedriver"
            if driver_path and os.path.exists(driver_path):
                from selenium.webdriver.chrome.service import Service as ChromeService
                self.driver = webdriver.Chrome(service=ChromeService(executable_path=driver_path), options=opts)
            else:
                self.driver = webdriver.Chrome(options=opts)

            self.driver.set_page_load_timeout(30)
            return True
        except Exception:
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                from selenium.webdriver.chrome.service import Service as ChromeService
                self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=opts)
                self.driver.set_page_load_timeout(30)
                return True
            except Exception:
                return False

    def _start_firefox(self, visible: bool = False) -> bool:
        """تشغيل Firefox / Firefox-ESR المعتمد في كالي لينكس مع ضبط البروكسي وتجاوز الـ SSL"""
        try:
            opts = FirefoxOptions()
            if not visible and self.headless:
                opts.add_argument("-headless")

            # مسارات كالي وويندوز لـ Firefox
            for bin_name in ["firefox-esr", "firefox"]:
                loc = shutil.which(bin_name)
                if loc:
                    opts.binary_location = loc
                    break

            # ضبط إعدادات التجاوز وتجاهل أخطاء الشهادات
            opts.set_preference("webdriver_accept_untrusted_certs", True)
            opts.set_preference("acceptInsecureCerts", True)
            opts.set_preference("security.insecure_field_warning.contextual.enabled", False)

            # توجيه ترافيك Firefox إلى Burp Suite
            if self.proxy:
                try:
                    p_host, p_port = self.proxy.split(":")
                    opts.set_preference("network.proxy.type", 1)
                    opts.set_preference("network.proxy.http", p_host)
                    opts.set_preference("network.proxy.http_port", int(p_port))
                    opts.set_preference("network.proxy.ssl", p_host)
                    opts.set_preference("network.proxy.ssl_port", int(p_port))
                    opts.set_preference("network.proxy.allow_hijacking_localhost", True)
                    opts.set_preference("network.proxy.no_proxies_on", "")
                except Exception:
                    pass

            driver_path = shutil.which("geckodriver") or "/usr/bin/geckodriver"
            if driver_path and os.path.exists(driver_path):
                from selenium.webdriver.firefox.service import Service as FirefoxService
                self.driver = webdriver.Firefox(service=FirefoxService(executable_path=driver_path), options=opts)
            else:
                self.driver = webdriver.Firefox(options=opts)

            self.driver.set_page_load_timeout(30)
            return True
        except Exception:
            try:
                from webdriver_manager.firefox import GeckoDriverManager
                from selenium.webdriver.firefox.service import Service as FirefoxService
                self.driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=opts)
                self.driver.set_page_load_timeout(30)
                return True
            except Exception:
                return False

    def _start_edge(self, visible: bool = False) -> bool:
        try:
            opts = EdgeOptions()
            if not visible and self.headless:
                opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--ignore-certificate-errors")
            if self.proxy:
                opts.add_argument(f"--proxy-server=http://{self.proxy}")

            self.driver = webdriver.Edge(options=opts)
            self.driver.set_page_load_timeout(30)
            return True
        except Exception:
            return False

    def navigate(self, url: str, wait: int = 2) -> bool:
        if not self.driver:
            return False
        try:
            self.driver.get(url)
            time.sleep(wait)
            return True
        except Exception as e:
            print(f"[Browser] Navigate failed: {e}")
            return False

    def get_source(self) -> str:
        return self.driver.page_source if self.driver else ""

    def get_title(self) -> str:
        return self.driver.title if self.driver else ""

    def get_current_url(self) -> str:
        return self.driver.current_url if self.driver else ""

    def screenshot(self, name: str = "") -> Optional[str]:
        if not self.driver:
            return None
        fn = name or f"ss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        p = str(self.ss_dir / fn)
        try:
            self.driver.save_screenshot(p)
            return p
        except Exception:
            return None

    def find_interactive_elements(self) -> Dict[str, Any]:
        """استخراج كل الأزرار والحقول والنماذج للتفاعل معها"""
        if not self.driver:
            return {}
        result = {"forms": [], "buttons": [], "links": [], "inputs": []}
        try:
            # Inputs
            for inp in self.driver.find_elements(By.TAG_NAME, "input"):
                t = inp.get_attribute("type") or "text"
                n = inp.get_attribute("name") or ""
                i = inp.get_attribute("id") or ""
                result["inputs"].append({"type": t, "name": n, "id": i})

            # Buttons
            for btn in self.driver.find_elements(By.TAG_NAME, "button"):
                txt = btn.text.strip()
                result["buttons"].append({"text": txt, "type": btn.get_attribute("type") or "button"})

            # Forms
            for form in self.driver.find_elements(By.TAG_NAME, "form"):
                action = form.get_attribute("action") or ""
                method = form.get_attribute("method") or "GET"
                fields = [{"name": i.get_attribute("name"), "type": i.get_attribute("type")}
                          for i in form.find_elements(By.TAG_NAME, "input")]
                result["forms"].append({"action": action, "method": method, "fields": fields})

            # Links
            for a in self.driver.find_elements(By.TAG_NAME, "a")[:30]:
                href = a.get_attribute("href") or ""
                if href.startswith("http"):
                    result["links"].append(href)
        except Exception as e:
            print(f"[Browser] Error finding elements: {e}")
        return result

    def click_element(self, by: By, value: str) -> bool:
        if not self.driver:
            return False
        try:
            elem = self.driver.find_element(by, value)
            elem.click()
            time.sleep(1)
            return True
        except Exception as e:
            print(f"[Browser] Click failed: {e}")
            return False

    def fill_input(self, selector: str, text: str) -> bool:
        if not self.driver:
            return False
        try:
            elem = self.driver.find_element(By.CSS_SELECTOR, selector)
            elem.clear()
            elem.send_keys(text)
            return True
        except Exception as e:
            print(f"[Browser] Fill input failed: {e}")
            return False

    def get_cookies(self) -> list:
        return self.driver.get_cookies() if self.driver else []

    def execute_js(self, script: str):
        """تنفيذ JavaScript في صفحة المتصفح الحالية"""
        if not self.driver:
            return None
        try:
            return self.driver.execute_script(script)
        except Exception as e:
            print(f"[Browser] JS execution failed: {e}")
            return None

    def auto_login(self, username: str, password: str, login_url: Optional[str] = None) -> bool:
        """تسجيل الدخول التلقائي في الموقع باستخدام اليوزر والباسورد"""
        if not self.driver:
            return False
        try:
            if login_url:
                self.navigate(login_url)
            
            # Find username field
            user_selectors = ["input[type='text']", "input[type='email']", "input[name*='user']", "input[name*='email']", "input[id*='user']", "input[id*='email']"]
            user_elem = None
            for sel in user_selectors:
                elems = self.driver.find_elements(By.CSS_SELECTOR, sel)
                if elems:
                    user_elem = elems[0]
                    break
            
            # Find password field
            pass_selectors = ["input[type='password']", "input[name*='pass']", "input[id*='pass']"]
            pass_elem = None
            for sel in pass_selectors:
                elems = self.driver.find_elements(By.CSS_SELECTOR, sel)
                if elems:
                    pass_elem = elems[0]
                    break
                    
            if user_elem and pass_elem:
                user_elem.clear()
                user_elem.send_keys(username)
                pass_elem.clear()
                pass_elem.send_keys(password)
                
                # Submit form or click login button
                submit_selectors = ["button[type='submit']", "input[type='submit']", "button", ".btn-login", "#login-btn"]
                clicked = False
                for sel in submit_selectors:
                    btns = self.driver.find_elements(By.CSS_SELECTOR, sel)
                    for b in btns:
                        if b.is_displayed():
                            b.click()
                            clicked = True
                            break
                    if clicked:
                        break
                if not clicked:
                    pass_elem.send_keys(Keys.RETURN)
                
                time.sleep(3)
                return True
        except Exception as e:
            print(f"[Browser] Auto login error: {e}")
        return False

    def stop(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
            self.active_browser = None
