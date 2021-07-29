package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs

#


# PR-AZR-0049-ARM
#

default netwatchFlowlogs = null

azure_attribute_absence["netwatchFlowlogs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.enabled
}


azure_issue["netwatchFlowlogs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.enabled != true
}

netwatchFlowlogs {
    lower(input.resources[_].type) == "microsoft.network/networkwatchers/flowlogs"
    not azure_attribute_absence["netwatchFlowlogs"]
    not azure_issue["netwatchFlowlogs"]
}

netwatchFlowlogs = false {
    azure_attribute_absence["netwatchFlowlogs"]
}

netwatchFlowlogs = false {
    azure_issue["netwatchFlowlogs"]
}

netwatchFlowlogs_miss_err = "Network watchers flowlog attribute 'enabled' is missing from the resource." {
    azure_attribute_absence["netwatchFlowlogs"]
}


netwatchFlowlogs_err = "Azure Network Watcher NSG flow logs are disabled" {
    azure_issue["netwatchFlowlogs"]
}


netwatchFlowlogs_metadata := {
    "Policy Code": "PR-AZR-0049-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs are disabled",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'._x005F_x000D_ _x005F_x000D_ NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:_x005F_x000D_ - Outbound and inbound flows on a per-rule basis._x005F_x000D_ - Network interface to which the flow applies._x005F_x000D_ - 5-tuple information about the flow (source/destination IP, source/destination port, protocol)._x005F_x000D_ - Whether the traffic was allowed or denied._x005F_x000D_ _x005F_x000D_ As a best practice, enable NSG flow logs to improve network visibility.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs"
}

# PR-AZR-0050-ARM
#

default netwatch_logs = null


azure_attribute_absence["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled
}

azure_issue["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == false
}

netwatch_logs {
    lower(input.resources[_].type) == "microsoft.network/networkwatchers/flowlogs"
    not azure_attribute_absence["netwatch_logs"]
    not azure_issue["netwatch_logs"]
}

netwatch_logs = false {
    azure_attribute_absence["netwatch_logs"]
}

netwatch_logs = false {
    azure_issue["netwatch_logs"]
}

netwatch_logs_miss_err = "Network watchers flowlog attribute 'enabled' is missing from the resource." {
    azure_attribute_absence["netwatch_logs"]
}


netwatch_logs_err = "Azure Network Watcher NSG flow logs are disabled" {
    azure_issue["netwatch_logs"]
}


netwatch_logs_metadata := {
    "Policy Code": "PR-AZR-0050-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs are disabled",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'._x005F_x000D_ _x005F_x000D_ NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:_x005F_x000D_ - Outbound and inbound flows on a per-rule basis._x005F_x000D_ - Network interface to which the flow applies._x005F_x000D_ - 5-tuple information about the flow (source/destination IP, source/destination port, protocol)._x005F_x000D_ - Whether the traffic was allowed or denied._x005F_x000D_ _x005F_x000D_ As a best practice, enable NSG flow logs to improve network visibility.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs"
}

#
# PR-AZR-0051-ARM
#

default netwatch_log_retention = null

azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.retentionPolicy.enabled
}

azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.retentionPolicy.days
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.retentionPolicy.enabled != true
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    to_number(resource.properties.retentionPolicy.days) < 90
}

netwatch_log_retention {
    lower(input.resources[_].type) == "microsoft.network/networkwatchers/flowlogs"
    not azure_attribute_absence["netwatch_log_retention"]
    not azure_issue["netwatch_log_retention"]
}

netwatch_log_retention = false {
    azure_attribute_absence["netwatch_log_retention"]
}

netwatch_log_retention = false {
    azure_issue["netwatch_log_retention"]
}

netwatch_log_retention_miss_err = "Network watchers flowlog attribute 'retentionPolicy' is missing from the resource." {
    azure_attribute_absence["netwatch_log_retention"]
}

netwatch_log_retention_err = "Azure Network Watcher NSG flow logs retention is less than 90 days" {
    azure_issue["netwatch_log_retention"]
}


netwatch_log_retention_metadata := {
    "Policy Code": "PR-AZR-0051-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs retention is less than 90 days",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs retention period is 90 days or less. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'._x005F_x000D_ _x005F_x000D_ NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:_x005F_x000D_ - Outbound and inbound flows on a per-rule basis._x005F_x000D_ - Network interface to which the flow applies._x005F_x000D_ - 5-tuple information about the flow (source/destination IP, source/destination port, protocol)._x005F_x000D_ - Whether the traffic was allowed or denied._x005F_x000D_ _x005F_x000D_ As a best practice, enable NSG flow logs and set the log retention period to at least 90 days.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs"
}
