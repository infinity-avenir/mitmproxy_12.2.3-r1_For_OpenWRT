-- LuCI controller for mitmproxy
-- Provides routing for all mitmproxy LuCI pages

module("luci.controller.mitmproxy", package.seeall)

function index()
    -- Main entry point in the LuCI navigation
    entry({"admin", "services", "mitmproxy"}, alias("admin", "services", "mitmproxy", "status"),
          _("mitmproxy"), 60).dependent = false

    -- Status / Dashboard page
    entry({"admin", "services", "mitmproxy", "status"}, template("mitmproxy/status"),
          _("Status"), 10).leaf = true

    -- Configuration page
    entry({"admin", "services", "mitmproxy", "settings"}, cbi("mitmproxy/settings"),
          _("Settings"), 20).leaf = true

    -- Rule management page
    entry({"admin", "services", "mitmproxy", "rules"}, cbi("mitmproxy/rules"),
          _("Rules"), 30).leaf = true

    -- Alerts / Logs page
    entry({"admin", "services", "mitmproxy", "alerts"}, template("mitmproxy/alerts"),
          _("Alerts"), 40).leaf = true

    -- Traffic Analysis page
    entry({"admin", "services", "mitmproxy", "traffic"}, template("mitmproxy/traffic"),
          _("Traffic Analysis"), 50).leaf = true

    -- API endpoints for AJAX calls
    entry({"admin", "services", "mitmproxy", "api", "status"}, call("api_status")).leaf = true
    entry({"admin", "services", "mitmproxy", "api", "alerts"}, call("api_alerts")).leaf = true
    entry({"admin", "services", "mitmproxy", "api", "flows"}, call("api_flows")).leaf = true
    entry({"admin", "services", "mitmproxy", "api", "stats"}, call("api_stats")).leaf = true
    entry({"admin", "services", "mitmproxy", "api", "action"}, call("api_action")).leaf = true
end

-- ── API: Service Status ──────────────────────────────────────────────

function api_status()
    local sys = require "luci.sys"
    local uci = require "luci.model.uci".cursor()
    local http = require "luci.http"
    local json = require "luci.jsonc"

    local status = {}

    -- Check if mitmproxy is running
    local pid = sys.exec("pgrep -f 'mitmweb\\|mitmdump' | head -1"):match("^%s*(.-)%s*$")
    status.running = (pid ~= "" and pid ~= nil)
    status.pid = pid or ""

    -- Get memory usage
    if status.running and pid ~= "" then
        local mem = sys.exec(string.format("ps -p %s -o rss= 2>/dev/null", pid))
        status.memory_kb = tonumber(mem:match("(%d+)")) or 0
        status.memory_mb = string.format("%.1f", status.memory_kb / 1024)
    else
        status.memory_kb = 0
        status.memory_mb = "0.0"
    end

    -- System memory
    local meminfo = sys.exec("free -m | awk 'NR==2{print $2,$3,$4,$7}'")
    local total, used, free, available = meminfo:match("(%d+)%s+(%d+)%s+(%d+)%s+(%d+)")
    status.sys_mem = {
        total     = tonumber(total) or 0,
        used      = tonumber(used) or 0,
        free      = tonumber(free) or 0,
        available = tonumber(available) or 0,
    }
    if status.sys_mem.total > 0 then
        status.sys_mem.percent = math.floor(status.sys_mem.used / status.sys_mem.total * 100)
    else
        status.sys_mem.percent = 0
    end

    -- Get enabled state from UCI
    status.enabled = uci:get("mitmproxy", "main", "enabled") == "1"
    status.listen_port = uci:get("mitmproxy", "main", "listen_port") or "8080"
    status.web_port = uci:get("mitmproxy", "main", "web_port") or "8081"
    status.mode = uci:get("mitmproxy", "main", "mode") or "regular"

    -- Uptime
    if status.running then
        local etime = sys.exec(string.format("ps -p %s -o etime= 2>/dev/null", pid)):match("^%s*(.-)%s*$")
        status.uptime = etime or "unknown"
    else
        status.uptime = "N/A"
    end

    -- Flow count (approximate from mitmweb API if available)
    local flow_count = sys.exec("curl -sf http://127.0.0.1:" ..
        (status.web_port or "8081") .. "/flows 2>/dev/null | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null")
    status.flow_count = tonumber(flow_count:match("(%d+)")) or 0

    -- Alert count from syslog
    local alert_count = sys.exec("logread | grep -ci 'mitmproxy.*\\(alert\\|warn\\|error\\)' 2>/dev/null")
    status.alert_count = tonumber(alert_count:match("(%d+)")) or 0

    -- CPU load
    local loadavg = sys.exec("cat /proc/loadavg"):match("^(.-)%s")
    status.loadavg = loadavg or "0.00"

    http.prepare_content("application/json")
    http.write(json.stringify(status))
end

-- ── API: Alerts / Logs ───────────────────────────────────────────────

function api_alerts()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local json = require "luci.jsonc"

    local alerts = {}

    -- Read last 50 mitmproxy-related log entries
    local log_output = sys.exec(
        "logread | grep -i 'mitmproxy\\|mitmdump\\|mitmweb' | tail -50"
    )

    local i = 0
    for line in log_output:gmatch("[^\n]+") do
        i = i + 1
        local ts, level, msg = line:match("^(.-)%s+(%S+)%s+(.+)$")
        if not ts then
            ts = ""
            level = "info"
            msg = line
        end

        -- Classify severity
        local severity = "info"
        if line:match("[Ee]rror") or line:match("ERROR") then
            severity = "error"
        elseif line:match("[Ww]arn") or line:match("WARN") then
            severity = "warning"
        elseif line:match("[Aa]lert") or line:match("ALERT") then
            severity = "alert"
        end

        alerts[#alerts + 1] = {
            id        = i,
            timestamp = ts,
            severity  = severity,
            message   = msg or line,
            source    = "syslog",
        }
    end

    -- Reverse so newest is first
    local reversed = {}
    for j = #alerts, 1, -1 do
        reversed[#reversed + 1] = alerts[j]
    end

    http.prepare_content("application/json")
    http.write(json.stringify({
        alerts = reversed,
        total  = #reversed,
    }))
end

-- ── API: Traffic Flows ───────────────────────────────────────────────

function api_flows()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local json = require "luci.jsonc"
    local uci = require "luci.model.uci".cursor()

    local web_port = uci:get("mitmproxy", "main", "web_port") or "8081"

    -- Proxy request to mitmweb API
    local flows_json = sys.exec(
        "curl -sf http://127.0.0.1:" .. web_port .. "/flows 2>/dev/null"
    )

    if flows_json and flows_json ~= "" then
        http.prepare_content("application/json")
        http.write(flows_json)
    else
        http.prepare_content("application/json")
        http.write(json.stringify({flows = {}, error = "mitmweb not available"}))
    end
end

-- ── API: Statistics ──────────────────────────────────────────────────

function api_stats()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local json = require "luci.jsonc"

    local stats = {}

    -- Network interface stats
    local rx = sys.exec("cat /sys/class/net/br-lan/statistics/rx_bytes 2>/dev/null")
    local tx = sys.exec("cat /sys/class/net/br-lan/statistics/tx_bytes 2>/dev/null")
    stats.rx_bytes = tonumber(rx:match("(%d+)")) or 0
    stats.tx_bytes = tonumber(tx:match("(%d+)")) or 0
    stats.rx_mb = string.format("%.1f", stats.rx_bytes / 1048576)
    stats.tx_mb = string.format("%.1f", stats.tx_bytes / 1048576)

    -- Connection tracking
    local conntrack = sys.exec("cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null")
    local conntrack_max = sys.exec("cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null")
    stats.connections = tonumber(conntrack:match("(%d+)")) or 0
    stats.connections_max = tonumber(conntrack_max:match("(%d+)")) or 0

    -- CPU temperature if available
    local temp = sys.exec("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null")
    local temp_val = tonumber(temp:match("(%d+)"))
    stats.cpu_temp = temp_val and string.format("%.1f", temp_val / 1000) or "N/A"

    http.prepare_content("application/json")
    http.write(json.stringify(stats))
end

-- ── API: Service Actions ─────────────────────────────────────────────

function api_action()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local json = require "luci.jsonc"

    local action = http.formvalue("action")
    local result = { success = false, message = "" }

    if action == "start" then
        os.execute("/etc/init.d/mitmproxy start")
        result.success = true
        result.message = "mitmproxy started"
    elseif action == "stop" then
        os.execute("/etc/init.d/mitmproxy stop")
        result.success = true
        result.message = "mitmproxy stopped"
    elseif action == "restart" then
        os.execute("/etc/init.d/mitmproxy restart")
        result.success = true
        result.message = "mitmproxy restarted"
    elseif action == "enable" then
        os.execute("/etc/init.d/mitmproxy enable")
        local uci = require "luci.model.uci".cursor()
        uci:set("mitmproxy", "main", "enabled", "1")
        uci:commit("mitmproxy")
        result.success = true
        result.message = "mitmproxy enabled at boot"
    elseif action == "disable" then
        os.execute("/etc/init.d/mitmproxy disable")
        local uci = require "luci.model.uci".cursor()
        uci:set("mitmproxy", "main", "enabled", "0")
        uci:commit("mitmproxy")
        result.success = true
        result.message = "mitmproxy disabled at boot"
    else
        result.message = "Unknown action: " .. (action or "nil")
    end

    http.prepare_content("application/json")
    http.write(json.stringify(result))
end
