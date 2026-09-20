module("luci.model.tailscale", package.seeall)

local jsonc = require "luci.jsonc"
local sys   = require "luci.sys"
local nixio = require "nixio"

local function translate(s)
	return require("luci.i18n").translate(s)
end

local function ts_bin()
	if nixio.fs.access("/usr/sbin/tailscale") then
		return "/usr/sbin/tailscale"
	elseif nixio.fs.access("/usr/bin/tailscale") then
		return "/usr/bin/tailscale"
	end
	return nil
end

-- Try the ucode ubus backend first. Returns nil if the object is not
-- registered (e.g. the base lacks ucode-mod-fs/ucode-mod-uci), so callers
-- can fall back to the CLI implementation below.
local function ubus_call(method, args)
	local ok, ubus = pcall(require, "ubus")
	if not ok or type(ubus) ~= "table" then
		return nil
	end
	local conn = ubus.connect()
	if not conn then
		return nil
	end
	local ok2, res = pcall(function()
		return conn:call("tailscale", method, args or {})
	end)
	conn:close()
	if ok2 then
		return res
	end
	return nil
end

local function status_cli()
	local st = {
		status = "",
		version = "",
		TUNMode = "",
		health = "",
		ipv4 = "Not running",
		ipv6 = nil,
		domain_name = "",
		peers = {}
	}

	local bin = ts_bin()
	if not bin then
		st.status = "not_installed"
		return st
	end

	local out = sys.exec(bin .. " status --json 2>/dev/null")
	local d = out and jsonc.parse(out)
	if type(d) ~= "table" then
		return st
	end

	st.version = d.Version or "Unknown"
	st.health = d.Health or ""
	st.TUNMode = d.TUN == nil and true or d.TUN
	if d.BackendState == "Running" then
		st.status = "running"
	elseif d.BackendState == "NeedsLogin" then
		st.status = "logout"
	end

	local self_ = d.Self or {}
	local ips = self_.TailscaleIPs or {}
	st.ipv4 = ips[1] or "No IP assigned"
	st.ipv6 = ips[2]
	st.domain_name = (d.CurrentTailnet and d.CurrentTailnet.Name) or ""

	for id, p in pairs(d.Peer or {}) do
		p = p or {}
		local pip = p.TailscaleIPs or {}
		local parts = {}
		for _, v in ipairs(pip) do
			parts[#parts + 1] = tostring(v)
		end
		st.peers[id] = {
			ip = table.concat(parts, "<br>"),
			hostname = (p.DNSName or p.HostName or ""):match("^([^%.]+)") or "",
			ostype = p.OS,
			online = p.Online,
			linkadress = (p.CurAddr and p.CurAddr ~= "" and p.CurAddr) or p.Relay or ""
		}
	end

	return st
end

function get_status()
	local r = ubus_call("get_status")
	if type(r) == "table" and r.status ~= nil then
		return r
	end
	return status_cli()
end

function logout()
	local r = ubus_call("do_logout")
	if type(r) == "table" then
		if r.error then
			return nil, r.error
		end
		return r
	end

	local bin = ts_bin()
	if not bin then
		return nil, translate("tailscale executable not found")
	end
	if sys.call(bin .. " logout >/dev/null 2>&1") == 0 then
		return { success = true }
	end
	return nil, translate("Failed to log out")
end

local function firewall_lua()
	local uci = require("luci.model.uci").cursor()
	local changed_network, changed_firewall = false, false

	if uci:get("network", "tailscale") == nil then
		uci:set("network", "tailscale", "interface")
		uci:set("network", "tailscale", "proto", "none")
		uci:set("network", "tailscale", "device", "tailscale0")
		changed_network = true
	elseif uci:get("network", "tailscale", "device") ~= "tailscale0" then
		uci:set("network", "tailscale", "device", "tailscale0")
		changed_network = true
	end

	local zone = nil
	uci:foreach("firewall", "zone", function(s)
		if s.name == "tailscale" then
			zone = s[".name"]
		end
	end)

	local fwd_l2t, fwd_t2l, fwd_t2w = false, false, false
	uci:foreach("firewall", "forwarding", function(s)
		if s.src == "lan" and s.dest == "tailscale" then fwd_l2t = true end
		if s.src == "tailscale" and s.dest == "lan" then fwd_t2l = true end
		if s.src == "tailscale" and s.dest == "wan" then fwd_t2w = true end
	end)

	if zone == nil then
		local zid = uci:add("firewall", "zone")
		uci:set("firewall", zid, "name", "tailscale")
		uci:set("firewall", zid, "input", "ACCEPT")
		uci:set("firewall", zid, "output", "ACCEPT")
		uci:set("firewall", zid, "forward", "ACCEPT")
		uci:set("firewall", zid, "masq", "1")
		uci:set("firewall", zid, "mtu_fix", "1")
		uci:set_list("firewall", zid, "network", { "tailscale" })
		changed_firewall = true
	else
		local nets = uci:get_list("firewall", zone, "network") or {}
		local has_ts = false
		for _, n in ipairs(nets) do
			if n == "tailscale" then
				has_ts = true
				break
			end
		end
		if not has_ts then
			nets[#nets + 1] = "tailscale"
			uci:set_list("firewall", zone, "network", nets)
			changed_firewall = true
		end
	end

	if not fwd_l2t then
		local fid = uci:add("firewall", "forwarding")
		uci:set("firewall", fid, "src", "lan")
		uci:set("firewall", fid, "dest", "tailscale")
		changed_firewall = true
	end
	if not fwd_t2l then
		local fid = uci:add("firewall", "forwarding")
		uci:set("firewall", fid, "src", "tailscale")
		uci:set("firewall", fid, "dest", "lan")
		changed_firewall = true
	end
	if not fwd_t2w then
		local fid = uci:add("firewall", "forwarding")
		uci:set("firewall", fid, "src", "tailscale")
		uci:set("firewall", fid, "dest", "wan")
		changed_firewall = true
	end

	if changed_network then
		uci:commit("network")
		sys.call("/etc/init.d/network reload >/dev/null 2>&1")
	end
	if changed_firewall then
		uci:commit("firewall")
		sys.call("/etc/init.d/firewall reload >/dev/null 2>&1")
	end

	return {
		success = true,
		changed_network = changed_network,
		changed_firewall = changed_firewall,
		message = (changed_network or changed_firewall)
			and translate("Tailscale firewall/interface configuration applied.")
			or translate("Tailscale firewall/interface already configured.")
	}
end

function setup_firewall()
	local r = ubus_call("setup_firewall")
	if type(r) == "table" then
		if r.error then
			return nil, r.error
		end
		return r
	end
	return firewall_lua()
end
