#
# PR-AZR-0082
#

package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

rulepass = false {
	input.type == "Microsoft.Sql/servers/firewallRules"
	input.properties.startIpAddress == "0.0.0.0"
}

rulepass = false {
	input.type == "Microsoft.Sql/servers/firewallRules"
	input.properties.endIpAddress == "0.0.0.0"
}
