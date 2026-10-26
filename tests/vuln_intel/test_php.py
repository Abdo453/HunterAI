"""PHP component classification is evidence-based and conservative."""
from __future__ import annotations

from core.vuln_intel.models import Confidence, PhpComponent
from core.vuln_intel.php import classify_php


def test_runtime_cpe(make_record, cpe_package):
    record = make_record(
        description="PHP 8.1.0 has a runtime issue.",
        affected=[cpe_package("php", "php", version="8.1.0")],
    )
    result = classify_php(record)
    assert result.involves_php is True
    assert result.component_type == PhpComponent.RUNTIME
    assert result.confidence == Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
    assert result.component_names == ["PHP runtime"]


def test_php_fpm_is_runtime_not_extension(make_record, cpe_package):
    record = make_record(
        description='PHP-FPM is affected.',
        affected=[cpe_package('php', 'php-fpm', version='8.1.0')],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.RUNTIME
    assert result.component_names == ['PHP runtime']


def test_extension_cpe(make_record, cpe_package):
    record = make_record(
        description="The PHP exif component is affected.",
        affected=[cpe_package("php", "exif", version="8.1.0")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.EXTENSION
    assert result.component_names == ["exif"]
    assert result.confidence == Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE


def test_framework_cpe(make_record, cpe_package):
    record = make_record(
        description="Laravel before 10.2.1 is affected.",
        affected=[cpe_package("laravel", "framework", version="10.2.0")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.FRAMEWORK
    assert result.frameworks == ["Laravel"]


def test_wordpress_core_is_framework(make_record, cpe_package):
    record = make_record(
        description="WordPress before 6.4.2 is affected.",
        affected=[cpe_package("wordpress", "wordpress", version="6.3.0")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.FRAMEWORK
    assert result.frameworks == ["WordPress"]


def test_wordpress_plugin_is_a_package(make_record, cpe_package):
    record = make_record(
        description="The Contact Form 7 plugin for WordPress is affected.",
        affected=[cpe_package("wordpress", "contact-form-7", version="5.0")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.PACKAGE
    assert "wordpress/contact-form-7" in result.component_names


def test_adobe_non_php_product_is_not_adobe_commerce(make_record, cpe_package):
    record = make_record(
        description="Adobe ColdFusion has an issue.",
        affected=[cpe_package("adobe", "coldfusion", version="2023")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.UNKNOWN
    assert result.involves_php is False


def test_composer_package(make_record, composer_package):
    record = make_record(
        description="A PHP logging library is affected.",
        affected=[composer_package("monolog/monolog")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.PACKAGE
    assert result.component_names == ["monolog/monolog"]


def test_laravel_composer_package_is_framework(make_record, composer_package):
    record = make_record(
        description="Laravel is affected.",
        affected=[composer_package("laravel/framework")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.FRAMEWORK
    assert result.frameworks == ["Laravel"]


def test_wordpress_plugin_composer_package_is_not_framework(make_record, composer_package):
    record = make_record(
        description="A WordPress plugin package is affected.",
        affected=[composer_package("wordpress/contact-form-7")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.PACKAGE


def test_php_application_text(make_record):
    record = make_record(
        description="A PHP application is vulnerable to XSS.",
        cwes=["CWE-79"],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.APPLICATION
    assert result.confidence == Confidence.STRONGLY_SUPPORTED


def test_php_mention_with_web_cwe_is_only_provisional_application(make_record):
    record = make_record(
        description="PHP is affected by SQL injection.",
        cwes=["CWE-89"],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.APPLICATION
    assert result.confidence == Confidence.PROVISIONAL


def test_php_server_configuration(make_record):
    record = make_record(
        description="The PHP expose_php directive leaks the version.",
        cwes=[],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.SERVER_CONFIG
    assert result.confidence == Confidence.STRONGLY_SUPPORTED


def test_bare_php_mention_is_not_a_component(make_record):
    record = make_record(description="This issue affects PHP.", cwes=[])
    result = classify_php(record)
    assert result.involves_php is False
    assert result.component_type == PhpComponent.UNKNOWN
    assert any("not evidence" in note for note in result.notes)


def test_generic_extension_phrase_without_name_is_not_enough(make_record):
    record = make_record(description="A PHP extension is vulnerable.", cwes=[])
    result = classify_php(record)
    assert result.component_type == PhpComponent.UNKNOWN
    assert any("generic PHP extension mention" in note for note in result.notes)


def test_explicit_extension_phrase_is_classified(make_record):
    record = make_record(
        description="The exif extension in PHP is vulnerable.",
        cwes=[],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.EXTENSION
    assert result.component_names == ["exif"]
    assert result.confidence == Confidence.STRONGLY_SUPPORTED


def test_runtime_cpe_plus_named_extension_is_extension(make_record, cpe_package):
    record = make_record(
        description="PHP 8.1.0's exif extension has a bug.",
        affected=[cpe_package("php", "php", version="8.1.0")],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.EXTENSION
    assert result.component_names == ["exif"]
    assert result.confidence == Confidence.STRONGLY_SUPPORTED
    assert any("named extension" in item for item in result.evidence)


def test_framework_text_with_php_context(make_record):
    record = make_record(
        description="WordPress before 6.4.2, written in PHP, is vulnerable.",
        cwes=[],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.FRAMEWORK
    assert result.frameworks == ["wordpress"]


def test_bare_extension_word_in_application_text_is_not_extension(make_record):
    record = make_record(
        description="A PHP application processes XML input.",
        cwes=[],
    )
    result = classify_php(record)
    assert result.component_type != PhpComponent.EXTENSION
    assert result.component_type == PhpComponent.APPLICATION


def test_no_php_context(make_record):
    record = make_record(description="A Linux kernel issue.", cwes=["CWE-787"])
    result = classify_php(record)
    assert result.involves_php is False
    assert result.component_type == PhpComponent.UNKNOWN
    assert any("No PHP-specific" in note for note in result.notes)


def test_wordpress_plugin_text_is_a_package_not_a_framework(make_record):
    record = make_record(
        description='A WordPress plugin written in PHP is vulnerable.',
        cwes=[],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.PACKAGE
    assert result.confidence == Confidence.PROVISIONAL
    assert result.component_names == ['wordpress plugin/module']


def test_php_application_mentioning_php_ini_is_application(make_record):
    record = make_record(
        description='A PHP application reads php.ini and is vulnerable.',
        cwes=[],
    )
    result = classify_php(record)
    assert result.component_type == PhpComponent.APPLICATION
