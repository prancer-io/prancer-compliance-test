package rule

# https://github.com/Azure/azure-service-operator/blob/master/config/samples/azure_v1alpha1_azuresqlfirewallrule.yaml

#
# PR-AZR-0082-ASO
#

default db_firewall = null

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.kind) == "azuresqlfirewallrule"
    not resource.spec.startIpAddress
}

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.kind) == "azuresqlfirewallrule"
    not resource.spec.endIpAddress
}

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.kind) == "azuresqlfirewallrule"
    resource.spec.startIpAddress == "0.0.0.0"
}

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.kind) == "azuresqlfirewallrule"
    resource.spec.endIpAddress == "0.0.0.0"
}

db_firewall {
    lower(input.resources[_].kind) == "azuresqlfirewallrule"
    not azure_issue["db_firewall"]
}

db_firewall = false {
    azure_issue["db_firewall"]
}

db_firewall_err = "SQL Server Firewall rules allow access to any Azure internal resources" {
    azure_issue["db_firewall"]
}

db_firewall_metadata := {
    "Policy Code": "PR-AZR-0082-ASO",
    "Type": "IaC",
    "Product": "ASO",
    "Language": "ASO template",
    "Policy Title": "SQL Server Firewall rules allow access to any Azure internal resources",
    "Policy Description": "Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.",
    "Resource Type": "AzureSqlFirewallRule",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/Azure/azure-service-operator/blob/master/config/samples/azure_v1alpha1_azuresqlfirewallrule.yaml"
}
