"""PHP-specific classification.

The goal is to answer *what kind of PHP component* an advisory concerns:

* PHP runtime (``php``),
* a bundled/PECL extension (``exif``, ``phar``, ``gd``, ...),
* a framework/CMS (Laravel, Symfony, WordPress, Drupal, Magento),
* a Composer package,
* a PHP application,
* server configuration (``php.ini`` directives).

A mention of the word "PHP" is **not** evidence of a vulnerability.  The
classifier only labels a component when it finds structured evidence (CPE /
package / ecosystem) or a concrete text signal (extension name, framework name,
application context) together with a PHP context.
"""
from __future__ import annotations

import re
from typing import List, Set

from .models import Confidence, PhpAnalysis, PhpComponent, VulnerabilityRecord

# Bundled / commonly deployed PHP extensions.  This is a classification aid,
# not a claim that every CVE in one of these names is an extension issue.
PHP_EXTENSIONS: Set[str] = {
    "bcmath",
    "calendar",
    "curl",
    "dom",
    "exif",
    "ffi",
    "fileinfo",
    "filter",
    "ftp",
    "gd",
    "gettext",
    "gmp",
    "iconv",
    "imap",
    "intl",
    "json",
    "ldap",
    "libxml",
    "mbstring",
    "mysqli",
    "mysqlnd",
    "opcache",
    "openssl",
    "pcntl",
    "pdo",
    "pdo_mysql",
    "pdo_pgsql",
    "pdo_sqlite",
    "pgsql",
    "phar",
    "posix",
    "readline",
    "session",
    "shmop",
    "simplexml",
    "soap",
    "sockets",
    "sodium",
    "sqlite3",
    "sysvmsg",
    "sysvsem",
    "sysvshm",
    "tidy",
    "tokenizer",
    "xml",
    "xmlreader",
    "xmlwriter",
    "xsl",
    "zip",
    "zlib",
}

FRAMEWORK_VENDORS = {
    "laravel": "Laravel",
    "symfony": "Symfony",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "magento": "Magento",
    "adobe": "Adobe Commerce",
}

FRAMEWORK_PACKAGES = {
    "laravel/framework": "Laravel",
    "symfony/symfony": "Symfony",
    "wordpress/wordpress": "WordPress",
    "drupal/core": "Drupal",
    "magento/product-community-edition": "Magento",
    "magento/product-enterprise-edition": "Magento",
    "adobe/commerce": "Adobe Commerce",
}

# Only component-style framework packages use a prefix.  CMS plugin/module
# packages (wordpress/*, drupal/*, magento/*) are packages, not the framework
# itself; the exact core packages are listed in FRAMEWORK_PACKAGES above.
FRAMEWORK_PREFIXES = {
    "laravel/": "Laravel",
    "symfony/": "Symfony",
}

# Focused set of web-application CWE classes.  Used only as supporting context
# for "PHP application", never as proof of exploitability.
WEB_CWES = {
    "CWE-22",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-98",
    "CWE-284",
    "CWE-285",
    "CWE-287",
    "CWE-352",
    "CWE-384",
    "CWE-434",
    "CWE-502",
    "CWE-601",
    "CWE-611",
    "CWE-639",
    "CWE-862",
    "CWE-863",
    "CWE-918",
}

def _text(record: VulnerabilityRecord) -> str:
    parts: List[str] = [
        record.title or "",
        record.description or "",
        record.summary or "",
    ]
    parts.extend(record.cwes)
    for ref in record.references:
        parts.append(ref.url)
        parts.extend(ref.tags)
    return "\n".join(parts).lower()


def _has_word(text: str, word: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


def _add(evidence: List[str], message: str) -> None:
    if message and message not in evidence:
        evidence.append(message)


def _explicit_extension_names(text: str) -> List[str]:
    """Return extension names that appear in an explicit extension phrase.

    A bare word such as ``xml`` or ``curl`` is not enough: a PHP application
    advisory can mention those words without concerning a PHP extension.  We
    require a phrase like "the exif extension", "php-exif module", or
    "extension for phar".
    """
    names: List[str] = []
    for name in PHP_EXTENSIONS:
        escaped = re.escape(name)
        pattern = (
            rf"\b(?:php[\s-]+)?{escaped}[\s-]+(?:extension|module)\b"
            rf"|\b(?:php[\s-]+)?(?:extension|module)[\s-]+(?:for[\s-]+)?{escaped}\b"
        )
        if re.search(pattern, text, re.IGNORECASE):
            names.append(name)
    return names


def classify_php(record: VulnerabilityRecord) -> PhpAnalysis:
    text = _text(record)
    text_php = _has_word(text, "php") or "php8" in text or "php7" in text

    evidence: List[str] = []
    runtime: List[str] = []
    extensions: List[str] = []
    frameworks: List[str] = []
    packages: List[str] = []

    for pkg in record.affected:
        vendor = (pkg.vendor or "").lower()
        product = (pkg.product or "").lower()
        package = (pkg.package_name or "").lower()
        cpe = (pkg.cpe or "").lower()
        eco = pkg.ecosystem.value

        if vendor in {"php", "php_group"} and (
            product in {"php", "php-fpm"}
            or package == "php"
            or ":php:php:" in cpe
        ):
            runtime.append("PHP runtime")
            _add(
                evidence,
                f"structured PHP runtime component: {pkg.cpe or pkg.package_name or 'php'}",
            )

        if product in PHP_EXTENSIONS or package in PHP_EXTENSIONS:
            extensions.append(product or package)
            _add(
                evidence,
                f"structured PHP extension component: {product or package}",
            )

        if vendor in FRAMEWORK_VENDORS:
            if vendor == "adobe" and product not in {"commerce", "magento"} and not package.startswith(
                "adobe/"
            ):
                # Adobe publishes many non-PHP products (ColdFusion, etc.).
                pass
            elif (
                vendor == "wordpress"
                and product
                and product != "wordpress"
                and package != "wordpress/wordpress"
            ):
                # A WordPress plugin is a package, not the WordPress framework.
                packages.append(f"wordpress/{product}")
                _add(
                    evidence,
                    f"structured WordPress plugin component: {product}",
                )
            else:
                frameworks.append(FRAMEWORK_VENDORS[vendor])
                _add(evidence, f"structured framework vendor: {vendor}")

        if package in FRAMEWORK_PACKAGES:
            frameworks.append(FRAMEWORK_PACKAGES[package])
            _add(evidence, f"structured framework package: {package}")
        else:
            for prefix, name in FRAMEWORK_PREFIXES.items():
                if package.startswith(prefix):
                    frameworks.append(name)
                    _add(evidence, f"structured framework package: {package}")
                    break

        if eco in {"composer", "packagist"} and package and "/" in package:
            if package not in FRAMEWORK_PACKAGES and not any(
                package.startswith(prefix) for prefix in FRAMEWORK_PREFIXES
            ):
                packages.append(package)
                _add(evidence, f"structured Composer package: {package}")

        if eco in {"wordpress", "drupal", "magento"}:
            frameworks.append(eco.title())
            _add(evidence, f"structured {eco} ecosystem")

        if eco == "php" and product and product not in {"php", "php-fpm"}:
            extensions.append(product)
            _add(evidence, f"structured PHP ecosystem component: {product}")

    extension_names = _explicit_extension_names(text)
    generic_extension_hint = any(
        phrase in text
        for phrase in ("php extension", "extension for php", "php module")
    )
    framework_names = sorted(
        name
        for name in {"laravel", "symfony", "wordpress", "drupal", "magento", "adobe commerce"}
        if _has_word(text, name)
    )
    plugin_hint = any(_has_word(text, word) for word in ("plugin", "theme", "module"))
    app_hint = any(
        phrase in text
        for phrase in (
            "php application",
            "php script",
            "php web app",
            "written in php",
            "php-based",
            "php app",
            "php website",
        )
    )
    config_hint = any(
        phrase in text
        for phrase in (
            "php.ini",
            "disable_functions",
            "open_basedir",
            "allow_url_include",
            "expose_php",
            "php configuration",
        )
    )
    web_cwe = bool(set(record.cwes) & WEB_CWES)

    component = PhpComponent.UNKNOWN
    confidence = Confidence.UNVERIFIED
    component_names: List[str] = []
    framework_names_out: List[str] = []
    notes: List[str] = []

    if frameworks:
        component = PhpComponent.FRAMEWORK
        confidence = Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
        framework_names_out = sorted(set(frameworks))
        component_names = framework_names_out
    elif extensions or (runtime and extension_names and text_php):
        component = PhpComponent.EXTENSION
        component_names = sorted(set(extensions or extension_names))
        if extensions:
            confidence = Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
        else:
            confidence = Confidence.STRONGLY_SUPPORTED
            _add(
                evidence,
                "PHP runtime CPE plus a named extension in the advisory text",
            )
    elif runtime:
        component = PhpComponent.RUNTIME
        confidence = Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
        component_names = ["PHP runtime"]
    elif packages:
        component = PhpComponent.PACKAGE
        confidence = Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
        component_names = sorted(set(packages))
    elif framework_names and text_php:
        if plugin_hint:
            # A WordPress/Drupal/Magento plugin, theme, or module is a package,
            # not the framework itself.
            component = PhpComponent.PACKAGE
            confidence = Confidence.PROVISIONAL
            component_names = [f"{framework_names[0]} plugin/module"]
            _add(
                evidence,
                "framework name with plugin/theme/module context in advisory text",
            )
        else:
            component = PhpComponent.FRAMEWORK
            confidence = Confidence.STRONGLY_SUPPORTED
            framework_names_out = sorted(set(framework_names))
            component_names = framework_names_out
            _add(evidence, "framework name in advisory text with PHP context")
    elif extension_names and text_php:
        component = PhpComponent.EXTENSION
        confidence = Confidence.STRONGLY_SUPPORTED
        component_names = sorted(set(extension_names))
        _add(evidence, "PHP extension name in an explicit extension phrase")
    elif config_hint and text_php and not app_hint:
        component = PhpComponent.SERVER_CONFIG
        confidence = Confidence.STRONGLY_SUPPORTED
        component_names = ["PHP configuration"]
        _add(evidence, "PHP configuration directive in advisory text")
    elif app_hint or (text_php and web_cwe):
        component = PhpComponent.APPLICATION
        confidence = (
            Confidence.STRONGLY_SUPPORTED if app_hint else Confidence.PROVISIONAL
        )
        component_names = ["PHP application"]
        if app_hint:
            _add(evidence, "application context in advisory text")
        if web_cwe:
            _add(
                evidence,
                "web-application CWE with PHP context: "
                + ", ".join(sorted(set(record.cwes) & WEB_CWES)),
            )

    involves_php = component != PhpComponent.UNKNOWN
    if text_php and not involves_php:
        notes.append(
            "PHP is mentioned, but no PHP-specific component or application "
            "context was found; this is not evidence of a vulnerability."
        )
    if generic_extension_hint and text_php and not involves_php:
        notes.append(
            "A generic PHP extension mention without a named extension is not "
            "enough to classify the component."
        )
    if not text_php and not involves_php:
        notes.append("No PHP-specific component or context was found.")

    return PhpAnalysis(
        involves_php=involves_php,
        component_type=component,
        component_names=component_names,
        frameworks=framework_names_out,
        evidence=evidence,
        confidence=confidence,
        notes=notes,
    )


__all__ = ["classify_php", "PHP_EXTENSIONS", "WEB_CWES"]
