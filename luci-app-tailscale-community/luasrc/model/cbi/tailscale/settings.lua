local m, s, o

m = Map("tailscale", translate("Tailscale"),
	translate("After Save & Apply, settings are applied to tailscale by /etc/init.d/tailscale-settings."))

s = m:section(NamedSection, "settings", "settings")
s.anonymous = true
s.addremove = false

o = s:option(Flag, "service_enabled", translate("Enable Tailscale Service"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "accept_routes", translate("Accept Routes"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "advertise_exit_node", translate("Advertise Exit Node"))
o.default = "0"
o.rmempty = false

o = s:option(DynamicList, "advertise_routes", translate("Advertise Routes"))
o.placeholder = "192.168.31.0/24"
o.validate = function(self, value)
	if type(value) ~= "string" or value == "" then
		return value
	end
	local ip, mask = value:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
	if ip and tonumber(mask) and tonumber(mask) >= 0 and tonumber(mask) <= 32 then
		return value
	end
	return nil, translate("Must be in CIDR format, e.g. 192.168.31.0/24")
end

o = s:option(Value, "exit_node", translate("Exit Node"))
o.placeholder = "exit-node-name-or-id"
o.rmempty = true

o = s:option(Flag, "exit_node_allow_lan_access", translate("Allow LAN Access"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "ssh", translate("Enable Tailscale SSH"))
o.default = "0"
o.rmempty = false

o = s:option(ListValue, "dns_mode", translate("DNS Mode"))
o:value("disabled", translate("Disabled"))
o:value("magicdns", translate("MagicDNS"))
o:value("openwrt_forward", translate("OpenWrt Forward"))
o.default = "disabled"

o = s:option(Flag, "shields_up", translate("Shields Up"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "runwebclient", translate("Enable Web Interface"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "nosnat", translate("Disable SNAT"))
o.default = "0"
o.rmempty = false

o = s:option(Value, "hostname", translate("Hostname"))
o.rmempty = true

o = s:option(Flag, "enable_relay", translate("Enable Peer Relay"))
o.default = "0"
o.rmempty = false

o = s:option(Value, "relay_server_port", translate("Peer Relay Port"))
o.default = "40000"
o.datatype = "port"

o = s:option(Value, "port", translate("Tailscale daemon listening port"))
o.default = "41641"
o.datatype = "port"

o = s:option(Value, "state_file", translate("State File"))
o.default = "/etc/tailscale/tailscaled.state"

o = s:option(Flag, "log_stdout", translate("Log stdout"))
o.default = "1"

o = s:option(Flag, "log_stderr", translate("Log stderr"))
o.default = "1"

o = s:option(ListValue, "fw_mode", translate("Firewall Mode"))
o:value("nftables", "nftables")
o:value("iptables", "iptables")
o.default = "iptables"

return m
