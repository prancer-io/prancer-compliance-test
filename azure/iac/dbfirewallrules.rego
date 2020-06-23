package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

#
# SQL Server Firewall rules allow access to any Azure internal resources (291)
#

default db_firewall = null

db_firewall {
    lower(input.type) == "microsoft.sql/servers/firewallrules"
    input.properties.startIpAddress != "0.0.0.0"
    input.properties.endIpAddress != "0.0.0.0"
}

db_firewall = false {
    lower(input.type) == "microsoft.sql/servers/firewallrules"
    input.properties.startIpAddress == "0.0.0.0"
}

db_firewall = false {
    lower(input.type) == "microsoft.sql/servers/firewallrules"
    input.properties.endIpAddress == "0.0.0.0"
}

db_firewall_err = "SQL Server Firewall rules allow access to any Azure internal resources" {
    db_firewall == false
}
