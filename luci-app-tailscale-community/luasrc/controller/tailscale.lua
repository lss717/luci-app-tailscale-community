module("luci.controller.tailscale", package.seeall)

local http  = require "luci.http"
local sys   = require "luci.sys"
local jsonc = require "luci.jsonc"
local translate = require("luci.i18n").translate

local function ts_bin()
	if nixio.fs.access("/usr/sbin/tailscale") then
		return "/usr/sbin/tailscale"
	elseif nixio.fs.access("/usr/bin/tailscale") then
		return "/usr/bin/tailscale"
	end
	return nil
end

local function shellquote(s)
	return "'" .. tostring(s or ""):gsub("'", "'\\''") .. "'"
end

local function ubus_call(method, args)
	local ubus = require "ubus"
	local conn = ubus.connect()
	if not conn then
		return nil, translate("Failed to connect to ubus")
	end
	local ok, res = pcall(function()
		return conn:call("tailscale", method, args or {})
	end)
	conn:close()
	if not ok then
		return nil, tostring(res)
	end
	return res
end

local function reply(res, err)
	http.prepare_content("application/json")
	if err then
		http.write_json({ error = err })
	else
		http.write_json(res or {})
	end
end

function index()
	local translate = require("luci.i18n").translate

	if not nixio.fs.access("/etc/config/tailscale") then
		return
	end

	entry({"admin", "vpn"}, firstchild(), "VPN", 45).dependent = false

	entry({"admin", "vpn", "tailscale"}, alias("admin", "vpn", "tailscale", "status"), "Tailscale", 90).dependent = false
	entry({"admin", "vpn", "tailscale", "status"}, template("tailscale/status"), translate("Status"), 10).leaf = true
	entry({"admin", "vpn", "tailscale", "settings"}, cbi("tailscale/settings"), translate("Settings"), 20).leaf = true

	entry({"admin", "vpn", "tailscale", "status_json"}, call("action_status")).leaf = true
	entry({"admin", "vpn", "tailscale", "login"}, call("action_login")).leaf = true
	entry({"admin", "vpn", "tailscale", "logout"}, call("action_logout")).leaf = true
	entry({"admin", "vpn", "tailscale", "firewall"}, call("action_firewall")).leaf = true
end

function action_status()
	local res, err = ubus_call("get_status")

	if not res then
		local bin = ts_bin()
		if bin then
			local out = sys.exec(bin .. " status --json 2>/dev/null")
			local parsed = out and jsonc.parse(out)
			if parsed then
				local ips = (parsed.Self and parsed.Self.TailscaleIPs) or {}
				res = {
					status = (parsed.BackendState == "Running") and "running"
					      or (parsed.BackendState == "NeedsLogin") and "logout" or "",
					version = parsed.Version or "",
					TUNMode = parsed.TUN or true,
					health = parsed.Health or "",
					ipv4 = ips[1] or "No IP assigned",
					ipv6 = ips[2],
					domain_name = (parsed.CurrentTailnet and parsed.CurrentTailnet.Name) or "",
					peers = {}
				}
			end
		end
	end

	if res then
		reply(res)
	else
		reply(nil, err or translate("Failed to get Tailscale status"))
	end
end

function action_login()
	local bin = ts_bin()
	if not bin then
		reply(nil, translate("tailscale executable not found"))
		return
	end

	local server = http.formvalue("loginserver") or ""
	local key    = http.formvalue("authkey") or ""

	local st = ubus_call("get_status")
	if st and st.status == "running" then
		reply(nil, translate("Tailscale is already logged in and running"))
		return
	end

	local cmd = bin .. " login"
	if server ~= "" then
		cmd = cmd .. " --login-server " .. shellquote(server)
		if key ~= "" then
			cmd = cmd .. " --auth-key " .. shellquote(key)
		end
	end

	sys.call("/bin/sh -c " .. shellquote(cmd .. " >/tmp/tailscale-login.log 2>&1 &"))

	local url
	for _ = 1, 15 do
		sys.call("sleep 2")
		local out = sys.exec(bin .. " status 2>/dev/null")
		if out then
			url = out:match("(https?://%S+)")
			if url then
				break
			end
		end
	end

	if url then
		reply({ url = url })
	else
		reply(nil, translate("No login link within 30 seconds, see /tmp/tailscale-login.log"))
	end
end

function action_logout()
	local res, err = ubus_call("do_logout")
	if res and res.error then
		reply(nil, res.error)
	elseif res then
		reply(res)
	else
		reply(nil, err)
	end
end

function action_firewall()
	local res, err = ubus_call("setup_firewall")
	if res and res.error then
		reply(nil, res.error)
	elseif res then
		reply(res)
	else
		reply(nil, err)
	end
end
