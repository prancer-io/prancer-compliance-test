package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

rulepass = false {
	input.properties.startIpAddress == "0.0.0.0"
}

rulepass = false {
	input.properties.endIpAddress == "0.0.0.0"
}
