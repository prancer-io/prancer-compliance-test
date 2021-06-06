#
# PR-AZR-0082
#

package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

rulepass = false {
    lower(input.type) == "microsoft.sql/servers/firewallrules"
    input.properties.startIpAddress == "0.0.0.0"
}

rulepass = false {
    lower(input.type) == "microsoft.sql/servers/firewallrules"
    input.properties.endIpAddress == "0.0.0.0"
}

metadata := {
    "Policy Code": "PR-AZR-0082",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "SQL Server Firewall rules allow access to any Azure internal resources",
    "Policy Description": "Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.",
    "Resource Type": "microsoft.sql/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules"
}
