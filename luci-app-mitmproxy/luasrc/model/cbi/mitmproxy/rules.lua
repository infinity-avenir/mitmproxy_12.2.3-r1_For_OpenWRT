-- LuCI CBI model for mitmproxy Rule Management
-- Manages blocklist, header/body modification, and map rules

local m, s, o

m = Map("mitmproxy", translate("mitmproxy Rules"),
    translate("Manage interception rules, blocklists, and traffic modification rules."))

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Blocklist Rules
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(TypedSection, "blocklist", translate("Blocklist Rules"),
    translate("Block matching requests with a specified HTTP status code. "
    .. "Format: /flow-filter/status-code (e.g. /~d ads.example.com/403)"))
s.addremove = true
s.anonymous = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enabled", translate("On"))
o.default = "1"
o.width = "5%"

o = s:option(Value, "name", translate("Name"))
o.placeholder = "Block ads"
o.width = "15%"

o = s:option(Value, "pattern", translate("Filter Pattern"),
    translate("mitmproxy flow filter expression"))
o.placeholder = "~d ads.example.com"
o.width = "30%"

o = s:option(ListValue, "status_code", translate("Response Code"))
o:value("403", "403 Forbidden")
o:value("404", "404 Not Found")
o:value("204", "204 No Content")
o:value("0", "0 No Response (drop)")
o.default = "403"
o.width = "15%"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Modify Headers Rules
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(TypedSection, "modify_header", translate("Modify Headers"),
    translate("Add, replace, or remove HTTP headers on matching flows. "
    .. "Format: /flow-filter/header-name/header-value"))
s.addremove = true
s.anonymous = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enabled", translate("On"))
o.default = "1"
o.width = "5%"

o = s:option(Value, "name", translate("Name"))
o.placeholder = "Add security header"
o.width = "15%"

o = s:option(ListValue, "direction", translate("Direction"))
o:value("request", translate("Request"))
o:value("response", translate("Response"))
o.default = "response"
o.width = "10%"

o = s:option(Value, "filter", translate("Flow Filter"))
o.placeholder = "~d example.com"
o.width = "15%"

o = s:option(Value, "header_name", translate("Header"))
o.placeholder = "X-Frame-Options"
o.width = "15%"

o = s:option(Value, "header_value", translate("Value"),
    translate("Leave empty to remove the header"))
o.placeholder = "DENY"
o.width = "15%"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Modify Body Rules
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(TypedSection, "modify_body", translate("Modify Body"),
    translate("Search and replace content in request or response bodies"))
s.addremove = true
s.anonymous = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enabled", translate("On"))
o.default = "1"
o.width = "5%"

o = s:option(Value, "name", translate("Name"))
o.placeholder = "Replace tracker"
o.width = "15%"

o = s:option(Value, "filter", translate("Flow Filter"))
o.placeholder = "~d example.com"
o.width = "15%"

o = s:option(Value, "search", translate("Search Pattern"),
    translate("Regex pattern to find"))
o.placeholder = "tracking-id-\\d+"
o.width = "20%"

o = s:option(Value, "replace", translate("Replacement"),
    translate("Replacement text (use @file for file-based replacement)"))
o.placeholder = "redacted"
o.width = "20%"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Map Local Rules
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(TypedSection, "map_local", translate("Map Local"),
    translate("Replace remote resources with local files"))
s.addremove = true
s.anonymous = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enabled", translate("On"))
o.default = "1"
o.width = "5%"

o = s:option(Value, "name", translate("Name"))
o.placeholder = "Local JS override"
o.width = "15%"

o = s:option(Value, "filter", translate("URL Pattern"))
o.placeholder = "~u /api/config.js"
o.width = "25%"

o = s:option(Value, "local_path", translate("Local File Path"))
o.placeholder = "/etc/mitmproxy/local/config.js"
o.width = "25%"

-- ═══════════════════════════════════════════════════════════════════════
-- Section: Map Remote Rules
-- ═══════════════════════════════════════════════════════════════════════
s = m:section(TypedSection, "map_remote", translate("Map Remote"),
    translate("Redirect requests to a different remote URL"))
s.addremove = true
s.anonymous = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enabled", translate("On"))
o.default = "1"
o.width = "5%"

o = s:option(Value, "name", translate("Name"))
o.placeholder = "API redirect"
o.width = "15%"

o = s:option(Value, "filter", translate("URL Pattern"))
o.placeholder = "~u /api/v1/"
o.width = "20%"

o = s:option(Value, "target_url", translate("Target URL"))
o.placeholder = "https://staging.example.com/api/v1/"
o.width = "25%"

return m
