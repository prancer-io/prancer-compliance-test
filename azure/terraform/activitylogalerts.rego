package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

array_element_contains(target_array, element_string) = true {
  contains(lower(target_array[_]), lower(element_string))
} else = false { true }

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert

#
# PR-AZR-TRF-MNT-001
#

default azure_monitor_activity_log_alert_enabled = null

# by default alert get enabled if not exist.
azure_attribute_absence["azure_monitor_activity_log_alert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.enabled
}

azure_issue["azure_monitor_activity_log_alert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    resource.properties.enabled != true
}

azure_monitor_activity_log_alert_enabled {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    azure_attribute_absence["azure_monitor_activity_log_alert_enabled"]
    not azure_issue["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["azure_monitor_activity_log_alert_enabled"]
    not azure_issue["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled = false {
    azure_issue["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled_err = "azurerm_monitor_activity_log_alert property 'enabled' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_issue["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Activity log alerts should be enabled",
    "Policy Description": "Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile

# Manages a Log Profile. A Log Profile configures how Activity Logs are exported.
# It's only possible to configure one Log Profile per Subscription. If you are trying to create more than one Log Profile, an error with StatusCode=409 will occur.
# PR-AZR-TRF-MNT-009
#

default azure_monitor_log_profile_retention = null

azure_attribute_absence["azure_monitor_log_profile_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    not resource.properties.retention_policy
}

azure_attribute_absence["azure_monitor_log_profile_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    not retention_policy.days
}

azure_issue["azure_monitor_log_profile_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    to_number(retention_policy.days) < 365
}

azure_monitor_log_profile_retention = false {
    azure_attribute_absence["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not azure_attribute_absence["azure_monitor_log_profile_retention"]
    not azure_issue["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention = false {
    azure_issue["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention_err = "azurerm_monitor_log_profile property 'retention_policy.days' is missing from the resource." {
    azure_attribute_absence["azure_monitor_log_profile_retention"]
} else = "Azure Activity log profile retention is currently not set to 365 days or greater" {
    azure_issue["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Activity log profile retention is set to 365 days or greater",
    "Policy Description": "This policy identifies azurerm_monitor_log_profile which have log retention less than 365 days. Activity Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access.",
    "Resource Type": "azurerm_monitor_log_profile",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile

# Manages a Log Profile. A Log Profile configures how Activity Logs are exported.
# It's only possible to configure one Log Profile per Subscription. If you are trying to create more than one Log Profile, an error with StatusCode=409 will occur.
# PR-AZR-TRF-MNT-010
#

default azure_monitor_log_profile_retention_enabled = null

azure_attribute_absence["azure_monitor_log_profile_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    not resource.properties.retention_policy
}

azure_attribute_absence["azure_monitor_log_profile_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    not retention_policy.enabled
}

azure_issue["azure_monitor_log_profile_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    retention_policy.enabled != true
}

azure_monitor_log_profile_retention_enabled = false {
    azure_attribute_absence["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not azure_attribute_absence["azure_monitor_log_profile_retention_enabled"]
    not azure_issue["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled = false {
    azure_issue["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled_err = "azurerm_monitor_log_profile property 'retention_policy.enabled' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["azure_monitor_log_profile_retention_enabled"]
} else = "Activity log profile retention is currently not enabled" {
    azure_issue["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Activity log profile retention should be enabled",
    "Policy Description": "This policy identifies azurerm_monitor_log_profile which dont have log retention enabled. Activity Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access.",
    "Resource Type": "azurerm_monitor_log_profile",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile

# Manages a Log Profile. A Log Profile configures how Activity Logs are exported.
# It's only possible to configure one Log Profile per Subscription. If you are trying to create more than one Log Profile, an error with StatusCode=409 will occur.
# PR-AZR-TRF-MNT-011
#

default azure_monitor_log_profile_capture_all_activities = null

azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    not resource.properties.categories
}

no_azure_issue["azure_monitor_log_profile_capture_all_activities"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    #categories := resource.properties.categories[_]
    #categories := resource.properties.categories
    array_contains(resource.properties.categories, "action")
    array_contains(resource.properties.categories, "delete")
    array_contains(resource.properties.categories, "write")
}

azure_monitor_log_profile_capture_all_activities = false {
    azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"]
    no_azure_issue["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities = false {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not no_azure_issue["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities_err = "azurerm_monitor_log_profile property 'categories' is missing from the resource." {
    azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"]
} else = "Activity log audit profile currently not configured to capture all the activities" {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not no_azure_issue["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Activity log audit profile should configure to capture all the activities",
    "Policy Description": "This policy identifies azurerm_monitor_log_profile which dont capture all type of activities. Activity Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access.",
    "Resource Type": "azurerm_monitor_log_profile",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile"
}


#
# PR-AZR-TRF-MNT-014
#

default alerts_to_create_update_sql_server_firewall_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_create_update_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.sql/servers/firewallrules/write";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_create_update_sql_server_firewall_rule_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"]
    not azure_issue["alerts_to_create_update_sql_server_firewall_rule_exist"]
}

alerts_to_create_update_sql_server_firewall_rule_exist = false {
    azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"]
}

alerts_to_create_update_sql_server_firewall_rule_exist = false {
    azure_issue["alerts_to_create_update_sql_server_firewall_rule_exist"]
}

alerts_to_create_update_sql_server_firewall_rule_exist_err = "Azure Activity log alert for create or update SQL server firewall rule currently not exist" {
    azure_issue["alerts_to_create_update_sql_server_firewall_rule_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"]
}

alerts_to_create_update_sql_server_firewall_rule_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for create or update SQL server firewall rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update SQL server firewall rule does not exist. Creating an activity log alert for Create or update SQL server firewall rule gives insight into SQL server firewall rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-015
#

default alerts_to_create_update_nsg_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_nsg_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_create_update_nsg_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_create_update_nsg_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.network/networksecuritygroups/write";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_create_update_nsg_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_create_update_nsg_exist"]
    not azure_issue["alerts_to_create_update_nsg_exist"]
}

alerts_to_create_update_nsg_exist = false {
    azure_attribute_absence["alerts_to_create_update_nsg_exist"]
}

alerts_to_create_update_nsg_exist = false {
    azure_issue["alerts_to_create_update_nsg_exist"]
}

alerts_to_create_update_nsg_exist_err = "Azure Activity log alert for create or update network security group currently not exist" {
    azure_issue["alerts_to_create_update_nsg_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_nsg_exist"]
}

alerts_to_create_update_nsg_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-015",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for create or update network security group should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update network security group does not exist. Creating an activity log alert for Create or update network security group gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-016
#

default alerts_to_create_update_nsg_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_create_update_nsg_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.network/networksecuritygroups/securityrules/write";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_create_update_nsg_rule_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"]
    not azure_issue["alerts_to_create_update_nsg_rule_exist"]
}

alerts_to_create_update_nsg_rule_exist = false {
    azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"]
}

alerts_to_create_update_nsg_rule_exist = false {
    azure_issue["alerts_to_create_update_nsg_rule_exist"]
}

alerts_to_create_update_nsg_rule_exist_err = "Azure Activity log alert for create or update network security group rule currently not exist" {
    azure_issue["alerts_to_create_update_nsg_rule_exist"]
} else = "azurerm_monitor_activity_log_alert property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"]
}

alerts_to_create_update_nsg_rule_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-016",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for create or update network security group rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update network security group rule does not exist. Creating an activity log alert for Create or update network security group rule gives insight into network rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-017
#

default alerts_to_create_update_security_solution_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_create_update_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_create_update_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.security/securitysolutions/write";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_create_update_security_solution_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_create_update_security_solution_exist"]
    not azure_issue["alerts_to_create_update_security_solution_exist"]
}

alerts_to_create_update_security_solution_exist = false {
    azure_attribute_absence["alerts_to_create_update_security_solution_exist"]
}

alerts_to_create_update_security_solution_exist = false {
    azure_issue["alerts_to_create_update_security_solution_exist"]
}

alerts_to_create_update_security_solution_exist_err = "Azure Activity log alert for create or update security solution currently not exist" {
    azure_issue["alerts_to_create_update_security_solution_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_security_solution_exist"]
}

alerts_to_create_update_security_solution_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-017",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for create or update security solution should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update security solution does not exist. Creating an activity log alert for Create or update security solution gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-018
#

default alerts_to_create_policy_assignment_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_create_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_create_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.authorization/policyassignments/write";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_create_policy_assignment_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_create_policy_assignment_exist"]
    not azure_issue["alerts_to_create_policy_assignment_exist"]
}

alerts_to_create_policy_assignment_exist = false {
    azure_attribute_absence["alerts_to_create_policy_assignment_exist"]
}

alerts_to_create_policy_assignment_exist = false {
    azure_issue["alerts_to_create_policy_assignment_exist"]
}

alerts_to_create_policy_assignment_exist_err = "Azure Activity log alert for create policy assignment currently not exist" {
    azure_issue["alerts_to_create_policy_assignment_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_create_policy_assignment_exist"]
}

alerts_to_create_policy_assignment_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-018",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for create policy assignment should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create policy assignment does not exist. Creating an activity log alert for Create policy assignment gives insight into changes done in azure policy - assignments and may reduce the time it takes to detect unsolicited changes.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-019
#

default alerts_to_delete_sql_server_firewall_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_delete_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.sql/servers/firewallrules/delete";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_delete_sql_server_firewall_rule_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"]
    not azure_issue["alerts_to_delete_sql_server_firewall_rule_exist"]
}

alerts_to_delete_sql_server_firewall_rule_exist = false {
    azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"]
}

alerts_to_delete_sql_server_firewall_rule_exist = false {
    azure_issue["alerts_to_delete_sql_server_firewall_rule_exist"]
}

alerts_to_delete_sql_server_firewall_rule_exist_err = "Azure Activity log alert for delete SQL server firewall rule currently not exist" {
    azure_issue["alerts_to_delete_sql_server_firewall_rule_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"]
}

alerts_to_delete_sql_server_firewall_rule_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-019",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for delete SQL server firewall rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete SQL server firewall rule does not exist. Creating an activity log alert for Delete SQL server firewall rule gives insight into SQL server firewall rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-020
#

default alerts_to_delete_network_security_group_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_network_security_group_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_delete_network_security_group_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_delete_network_security_group_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.network/networksecuritygroups/delete";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_delete_network_security_group_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_delete_network_security_group_exist"]
    not azure_issue["alerts_to_delete_network_security_group_exist"]
}

alerts_to_delete_network_security_group_exist = false {
    azure_attribute_absence["alerts_to_delete_network_security_group_exist"]
}

alerts_to_delete_network_security_group_exist = false {
    azure_issue["alerts_to_delete_network_security_group_exist"]
}

alerts_to_delete_network_security_group_exist_err = "Azure Activity log alert for delete network security group currently not exist" {
    azure_issue["alerts_to_delete_network_security_group_exist"]
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_network_security_group_exist"]
}

alerts_to_delete_network_security_group_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-020",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for delete network security group should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete network security group does not exist. Creating an activity log alert for the Delete network security group gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-021
#

default alerts_to_delete_network_security_group_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_delete_network_security_group_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.network/networksecuritygroups/securityrules/delete";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_delete_network_security_group_rule_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"]
    not azure_issue["alerts_to_delete_network_security_group_rule_exist"]
}

alerts_to_delete_network_security_group_rule_exist = false {
    azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"]
}

alerts_to_delete_network_security_group_rule_exist = false {
    azure_issue["alerts_to_delete_network_security_group_rule_exist"]
}

alerts_to_delete_network_security_group_rule_exist_err = "Azure Activity log alert for delete network security group rule currently not exist" {
    azure_issue["alerts_to_delete_network_security_group_rule_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"]
}

alerts_to_delete_network_security_group_rule_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-021",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for delete network security group rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete network security group rule does not exist. Creating an activity log alert for Delete network security group rule gives insight into network rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-022
#

default alerts_to_delete_security_solution_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_delete_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_delete_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.security/securitysolutions/delete";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_delete_security_solution_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_delete_security_solution_exist"]
    not azure_issue["alerts_to_delete_security_solution_exist"]
}

alerts_to_delete_security_solution_exist = false {
    azure_attribute_absence["alerts_to_delete_security_solution_exist"]
}

alerts_to_delete_security_solution_exist = false {
    azure_issue["alerts_to_delete_security_solution_exist"]
}

alerts_to_delete_security_solution_exist_err = "Azure Activity log alert for delete security solution currently not exist" {
    azure_issue["alerts_to_delete_security_solution_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_security_solution_exist"]
}

alerts_to_delete_security_solution_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-022",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for delete security solution should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete security solution does not exist. Creating an activity log alert for Delete security solution gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-023
#

default alerts_to_update_security_policy_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_update_security_policy_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_update_security_policy_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_update_security_policy_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.security/policies/write";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_update_security_policy_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_update_security_policy_exist"]
    not azure_issue["alerts_to_update_security_policy_exist"]
}

alerts_to_update_security_policy_exist = false {
    azure_attribute_absence["alerts_to_update_security_policy_exist"]
}

alerts_to_update_security_policy_exist = false {
    azure_issue["alerts_to_update_security_policy_exist"]
}

alerts_to_update_security_policy_exist_err = "Azure Activity log alert for update security policy currently not exist" {
    azure_issue["alerts_to_update_security_policy_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_update_security_policy_exist"]
}

alerts_to_update_security_policy_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-023",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for update security policy should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Update security policy does not exist. Creating an activity log alert for Update security policy gives insight into changes to security policy and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


#
# PR-AZR-TRF-MNT-024
#

default alerts_to_delete_policy_assignment_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.criteria
}

azure_attribute_absence["alerts_to_delete_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    criteria := resource.properties.criteria[_]
    not criteria.operation_name
}

azure_issue["alerts_to_delete_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count([c | criteria := resource.properties.criteria[_];
              lower(criteria.operation_name) == "microsoft.authorization/policyassignments/delete";
              not array_element_contains(resource.properties.scopes, "azurerm_resource_group");
              c := 1]) == 0
}

alerts_to_delete_policy_assignment_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["alerts_to_delete_policy_assignment_exist"]
    not azure_issue["alerts_to_delete_policy_assignment_exist"]
}

alerts_to_delete_policy_assignment_exist = false {
    azure_attribute_absence["alerts_to_delete_policy_assignment_exist"]
}

alerts_to_delete_policy_assignment_exist = false {
    azure_issue["alerts_to_delete_policy_assignment_exist"]
}

alerts_to_delete_policy_assignment_exist_err = "Azure Activity log alert for delete policy assignment currently not exist" {
    azure_issue["alerts_to_delete_policy_assignment_exist"]
} else = "azurerm_monitor_activity_log_alert property criteria.operation_name is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_policy_assignment_exist"]
}

alerts_to_delete_policy_assignment_exist_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-024",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Activity log alert for delete policy assignment should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete policy assignment does not exist. Creating an activity log alert for Delete policy assignment gives insight into changes done in azure policy - assignments and may reduce the time it takes to detect unsolicited changes.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}