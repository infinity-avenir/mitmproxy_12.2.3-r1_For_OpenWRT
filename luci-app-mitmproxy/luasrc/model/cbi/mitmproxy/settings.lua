-- LuCI CBI model for mitmproxy Settings page
-- Provides the complete configuration interface

local m, s, o

m = Map("mitmproxy", translate("mitmproxy Settings"),
    translate("Configure mitmproxy HTTP proxy and traffic inspection settings. "
    .. "Changes take effect after restarting the service."))

-- ═══════════════════════════════════════════════════════════════════════
-- Section: General Settings
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(NamedSection, "main", "mitmproxy",
    translate("General Settings"))
s.addremove = false
s.anonymous = false

o = s:option(Flag, "enabled", translate("Enable Service"),
    translate("Start mitmproxy proxy service"))
o.default = "0"
o.rmempty = false

o = s:option(Value, "listen_host", translate("Listen Address"),
    translate("IP address to bind the proxy to. Use 0.0.0.0 for all interfaces."))
o.default = "0.0.0.0"
o.datatype = "ipaddr"
o.rmempty = false

o = s:option(Value, "listen_port", translate("Proxy Port"),
    translate("Port for the proxy server"))
o.default = "8080"
o.datatype = "port"
o.rmempty = false

o = s:option(ListValue, "mode", translate("Proxy Mode"),
    translate("Operating mode of the proxy"))
o:value("regular", translate("Regular HTTP Proxy"))
o:value("transparent", translate("Transparent Proxy"))
o:value("socks5", translate("SOCKS5 Proxy"))
o:value("upstream", translate("Upstream Proxy"))
o:value("reverse", translate("Reverse Proxy"))
o.default = "regular"

o = s:option(Value, "upstream_server", translate("Upstream/Reverse Server"),
    translate("Target server URL for upstream or reverse mode (e.g. https://example.com)"))
o:depends("mode", "upstream")
o:depends("mode", "reverse")
o.placeholder = "https://example.com"

o = s:option(Flag, "ssl_insecure", translate("SSL Insecure"),
    translate("Do not verify upstream server SSL/TLS certificates"))
o.default = "0"

o = s:option(Value, "confdir", translate("Config Directory"),
    translate("Path to mitmproxy configuration and certificates directory"))
o.default = "/etc/mitmproxy/certs"
o.rmempty = false

o = s:option(Value, "config_file", translate("Config File Path"),
    translate("Path to the mitmproxy YAML config file"))
o.default = "/etc/mitmproxy/config.yaml"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Web Interface
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(NamedSection, "main", "mitmproxy",
    translate("Web Interface (mitmweb)"))
s.addremove = false

o = s:option(Value, "web_host", translate("Web UI Listen Address"),
    translate("Address for the mitmweb interface"))
o.default = "0.0.0.0"
o.datatype = "ipaddr"

o = s:option(Value, "web_port", translate("Web UI Port"),
    translate("Port for the mitmweb interface"))
o.default = "8081"
o.datatype = "port"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Traffic Analysis
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(NamedSection, "traffic_analysis", "mitmproxy",
    translate("Traffic Analysis"))
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable Traffic Analysis"),
    translate("Enable traffic monitoring and behavior analysis"))
o.default = "0"

o = s:option(Flag, "flow_collection", translate("Flow Collection"),
    translate("Collect and store HTTP/HTTPS flow data for analysis. "
    .. "Records request/response metadata, headers, and optionally body content."))
o.default = "1"

o = s:option(Value, "max_flows", translate("Max Stored Flows"),
    translate("Maximum number of flows to keep in memory. "
    .. "Older flows are discarded when this limit is reached."))
o.default = "10000"
o.datatype = "uinteger"

o = s:option(Flag, "behavior_analysis", translate("Traffic Behavior Analysis"),
    translate("Analyze traffic patterns to detect anomalies, "
    .. "unusual request volumes, and suspicious connection behavior."))
o.default = "0"

o = s:option(ListValue, "behavior_sensitivity", translate("Detection Sensitivity"),
    translate("Sensitivity level for behavior anomaly detection"))
o:value("low", translate("Low - Fewer false positives"))
o:value("medium", translate("Medium - Balanced"))
o:value("high", translate("High - More sensitive"))
o.default = "medium"
o:depends("behavior_analysis", "1")

o = s:option(Flag, "ai_analysis", translate("AI-Assisted Analysis"),
    translate("Use pattern recognition to classify traffic, "
    .. "detect potential threats, and provide intelligent alerts. "
    .. "Requires additional processing resources."))
o.default = "0"

o = s:option(ListValue, "ai_model", translate("Analysis Model"),
    translate("AI analysis model to use for traffic classification"))
o:value("basic", translate("Basic - Rule-based heuristics"))
o:value("advanced", translate("Advanced - ML pattern matching"))
o.default = "basic"
o:depends("ai_analysis", "1")

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Interception Settings
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(NamedSection, "interception", "mitmproxy",
    translate("Interception Settings"))
s.addremove = false

o = s:option(Value, "intercept", translate("Intercept Filter"),
    translate("Flow filter expression for interception (mitmproxy filter syntax). "
    .. "Example: ~d example.com & ~m GET"))
o.placeholder = "~d example.com"

o = s:option(DynamicList, "ignore_hosts", translate("Ignore Hosts"),
    translate("Regex patterns of hosts to ignore (pass through without inspection). "
    .. "One pattern per line."))
o.placeholder = ".*\\.googleapis\\.com"

o = s:option(DynamicList, "allow_hosts", translate("Allow Hosts"),
    translate("Only intercept traffic matching these host patterns. "
    .. "If set, all non-matching traffic is passed through."))
o.placeholder = ".*\\.example\\.com"

o = s:option(Flag, "anticache", translate("Anti-Cache"),
    translate("Strip cache headers from requests and responses to force "
    .. "content to be fetched fresh every time."))
o.default = "0"

o = s:option(Flag, "anticomp", translate("Anti-Compression"),
    translate("Strip compression headers to force uncompressed responses, "
    .. "making content inspection easier."))
o.default = "0"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Logging
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(NamedSection, "logging", "mitmproxy",
    translate("Logging"))
s.addremove = false

o = s:option(ListValue, "log_level", translate("Log Level"),
    translate("Verbosity of log output"))
o:value("error", translate("Error"))
o:value("warn", translate("Warning"))
o:value("info", translate("Info"))
o:value("debug", translate("Debug"))
o.default = "info"

o = s:option(ListValue, "flow_detail", translate("Flow Detail Level"),
    translate("Level of detail for flow logging (0=none, 4=very verbose)"))
o:value("0", translate("0 - None"))
o:value("1", translate("1 - Summary"))
o:value("2", translate("2 - Full headers"))
o:value("3", translate("3 - Headers + content"))
o:value("4", translate("4 - Headers + full content"))
o.default = "1"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Advanced / Script
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(NamedSection, "main", "mitmproxy",
    translate("Advanced"))
s.addremove = false

o = s:option(Value, "script", translate("Custom Script"),
    translate("Path to a Python script loaded by mitmproxy for custom traffic processing"))
o.placeholder = "/etc/mitmproxy/scripts/custom.py"

o = s:option(DynamicList, "extra_args", translate("Extra Arguments"),
    translate("Additional command-line arguments passed to mitmproxy"))
o.placeholder = "--set connection_strategy=lazy"

return m
