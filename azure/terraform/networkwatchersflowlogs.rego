package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log

#


# PR-AZR-0049-TRF
#

default netwatchFlowlogs = null

azure_attribute_absence["netwatchFlowlogs"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    not resource.properties.enabled
}

azure_issue["netwatchFlowlogs"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    resource.properties.enabled != true
}

netwatchFlowlogs {
    lower(input.resources[_].type) == "azurerm_network_watcher_flow_log"
    not azure_attribute_absence["netwatchFlowlogs"]
    not azure_issue["netwatchFlowlogs"]
}

netwatchFlowlogs = false {
    azure_attribute_absence["netwatchFlowlogs"]
}

netwatchFlowlogs = false {
    azure_issue["netwatchFlowlogs"]
}

netwatchFlowlogs_err = "azurerm_network_watcher_flow_log property 'enabled' is missing from the resource." {
    azure_attribute_absence["netwatchFlowlogs"]
} else = "Azure Network Watcher NSG flow log is disabled" {
    azure_issue["netwatchFlowlogs"]
}

netwatchFlowlogs_metadata := {
    "Policy Code": "PR-AZR-0049-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs should be enabled",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'._x005F_x000D_ _x005F_x000D_ NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:_x005F_x000D_ - Outbound and inbound flows on a per-rule basis._x005F_x000D_ - Network interface to which the flow applies._x005F_x000D_ - 5-tuple information about the flow (source/destination IP, source/destination port, protocol)._x005F_x000D_ - Whether the traffic was allowed or denied._x005F_x000D_ _x005F_x000D_ As a best practice, enable NSG flow logs to improve network visibility.",
    "Resource Type": "azurerm_network_watcher_flow_log",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log"
}

# PR-AZR-0050-TRF
#

default netwatch_logs = null


azure_attribute_absence["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    not resource.properties.traffic_analytics
}

azure_attribute_absence["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    traffic_analytics := resource.properties.traffic_analytics[_]
    not traffic_analytics.enabled
}

azure_issue["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    traffic_analytics := resource.properties.traffic_analytics[_]
    traffic_analytics.enabled == false
}

netwatch_logs {
    lower(input.resources[_].type) == "azurerm_network_watcher_flow_log"
    not azure_attribute_absence["netwatch_logs"]
    not azure_issue["netwatch_logs"]
}

netwatch_logs = false {
    azure_attribute_absence["netwatch_logs"]
}

netwatch_logs = false {
    azure_issue["netwatch_logs"]
}

netwatch_logs_err = "traffic_analytics property 'enabled' is missing from the azurerm_network_watcher_flow_log resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["netwatch_logs"]
} else = "Azure Network Watcher NSG traffic analytics is currently not enabled" {
    azure_issue["netwatch_logs"]
}

netwatch_logs_metadata := {
    "Policy Code": "PR-AZR-0050-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) traffic analytics should be enabled",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'._x005F_x000D_ _x005F_x000D_ NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:_x005F_x000D_ - Outbound and inbound flows on a per-rule basis._x005F_x000D_ - Network interface to which the flow applies._x005F_x000D_ - 5-tuple information about the flow (source/destination IP, source/destination port, protocol)._x005F_x000D_ - Whether the traffic was allowed or denied._x005F_x000D_ _x005F_x000D_ As a best practice, enable NSG flow logs to improve network visibility.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log"
}

#
# PR-AZR-0051-TRF
#

default netwatch_log_retention = null

azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    not resource.properties.retention_policy
}

azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    retention_policy := resource.properties.retention_policy[_]
    not retention_policy.enabled
}

azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    retention_policy := resource.properties.retention_policy[_]
    not retention_policy.days
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    retention_policy := resource.properties.retention_policy[_]
    retention_policy.enabled != true
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    retention_policy := resource.properties.retention_policy[_]
    to_number(retention_policy.days) < 90
}

netwatch_log_retention {
    lower(input.resources[_].type) == "azurerm_network_watcher_flow_log"
    not azure_attribute_absence["netwatch_log_retention"]
    not azure_issue["netwatch_log_retention"]
}

netwatch_log_retention = false {
    azure_attribute_absence["netwatch_log_retention"]
}

netwatch_log_retention = false {
    azure_issue["netwatch_log_retention"]
}

netwatch_log_retention_err = "azurerm_network_watcher_flow_log property 'retention_policy.enabled' or 'retention_policy.days' or both are missing from the resource." {
    azure_attribute_absence["netwatch_log_retention"]
} else = "Azure Network Watcher NSG flow logs retention is currently not equal or greater than 90 days" {
    azure_issue["netwatch_log_retention"]
}


netwatch_log_retention_metadata := {
    "Policy Code": "PR-AZR-0051-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs retention should be equal or greater than 90 days",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs retention period is 90 days or less. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'._x005F_x000D_ _x005F_x000D_ NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:_x005F_x000D_ - Outbound and inbound flows on a per-rule basis._x005F_x000D_ - Network interface to which the flow applies._x005F_x000D_ - 5-tuple information about the flow (source/destination IP, source/destination port, protocol)._x005F_x000D_ - Whether the traffic was allowed or denied._x005F_x000D_ _x005F_x000D_ As a best practice, enable NSG flow logs and set the log retention period to at least 90 days.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log"
}
