package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs

#


# PR-AZR-CLD-NTW-001
#

default netwatchFlowlogs = null

azure_attribute_absence["netwatchFlowlogs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.enabled
}

source_path[{"netwatchFlowlogs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","enabled"]]
    }
}


azure_issue["netwatchFlowlogs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.enabled != true
}

source_path[{"netwatchFlowlogs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","enabled"]]
    }
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


netwatchFlowlogs_err = "Azure Network Watcher NSG flow log is currently not enabled" {
    azure_issue["netwatchFlowlogs"]
}


netwatchFlowlogs_metadata := {
    "Policy Code": "PR-AZR-CLD-NTW-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs should be enabled",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'.<br><br>NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:<br>- Outbound and inbound flows on a per-rule basis.<br>- Network interface to which the flow applies.<br>- 5-tuple information about the flow (source/destination IP, source/destination port, protocol).<br>- Whether the traffic was allowed or denied.<br><br>As a best practice, enable NSG flow logs to improve network visibility.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs"
}

# PR-AZR-CLD-NTW-002
#

default netwatch_logs = null


azure_attribute_absence["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled
}

source_path[{"netwatch_logs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","flowAnalyticsConfiguration","networkWatcherFlowAnalyticsConfiguration","enabled"]]
    }
}

azure_issue["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == false
}

source_path[{"netwatch_logs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == false
    metadata:= {
        "resource_path": [["resources",i,"properties","flowAnalyticsConfiguration","networkWatcherFlowAnalyticsConfiguration","enabled"]]
    }
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

netwatch_logs_miss_err = "Network watchers flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration attribute 'enabled' is missing from the resource." {
    azure_attribute_absence["netwatch_logs"]
}


netwatch_logs_err = "Azure Network Watcher NSG traffic analytics is currently not enabled" {
    azure_issue["netwatch_logs"]
}


netwatch_logs_metadata := {
    "Policy Code": "PR-AZR-CLD-NTW-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) traffic analytics should be enabled",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'.<br><br>NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:<br>- Outbound and inbound flows on a per-rule basis.<br>- Network interface to which the flow applies.<br>- 5-tuple information about the flow (source/destination IP, source/destination port, protocol).<br>- Whether the traffic was allowed or denied.<br><br>As a best practice, enable NSG flow logs to improve network visibility.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs"
}

#
# PR-AZR-CLD-NTW-003
#

default netwatch_log_retention = null

azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.retentionPolicy.enabled
}

source_path[{"netwatch_log_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.retentionPolicy.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","enabled"]]
    }
}


azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.retentionPolicy.days
}

source_path[{"netwatch_log_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.retentionPolicy.days
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","days"]]
    }
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.retentionPolicy.enabled != true
}

source_path[{"netwatch_log_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.retentionPolicy.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","enabled"]]
    }
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    to_number(resource.properties.retentionPolicy.days) < 90
}

source_path[{"netwatch_log_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    to_number(resource.properties.retentionPolicy.days) < 90
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","days"]]
    }
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

netwatch_log_retention_err = "Azure Network Watcher NSG flow logs retention is currently not equal or greater than 90 days" {
    azure_issue["netwatch_log_retention"]
}


netwatch_log_retention_metadata := {
    "Policy Code": "PR-AZR-CLD-NTW-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs retention should be equal or greater than 90 days",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs retention period is 90 days or less. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'.<br><br>NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:<br>- Outbound and inbound flows on a per-rule basis.<br>- Network interface to which the flow applies.<br>- 5-tuple information about the flow (source/destination IP, source/destination port, protocol).<br>- Whether the traffic was allowed or denied.<br><br>As a best practice, enable NSG flow logs and set the log retention period to at least 90 days.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs"
}
