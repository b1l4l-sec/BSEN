from bsen.core.plugin import discover_plugins

PLUGIN_PACKAGES = [
    "bsen.scanners.common",
    "bsen.scanners.windows",
    "bsen.scanners.linux",
]


def test_discovers_at_least_the_common_scanners():
    plugins = discover_plugins(PLUGIN_PACKAGES)
    names = {p.name for p in plugins}
    assert "system_scanner" in names
    assert "network_scanner" in names
    assert "process_scanner" in names


def test_discovered_plugins_are_supported_on_this_host():
    plugins = discover_plugins(PLUGIN_PACKAGES)
    for p in plugins:
        assert p.supported_here()


def test_every_plugin_scan_returns_a_result_without_raising():
    plugins = discover_plugins(PLUGIN_PACKAGES)
    for p in plugins:
        result = p.safe_scan()
        assert result.plugin_name == p.name
        # safe_scan must never raise - error (if any) is captured on the result
        assert hasattr(result, "findings")
