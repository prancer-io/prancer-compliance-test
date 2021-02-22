#
# PR-AZR-0096
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies

rulepass {
	input.type == "Microsoft.Sql/servers/databases/securityAlertPolicies"
	input.properties.state == "Enabled"
}
