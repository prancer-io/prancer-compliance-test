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

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts

#
# PR-AZR-CLD-MNT-001
#

default alerts = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.enabled
}

azure_issue["alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    resource.properties.enabled != true
}

alerts {
    azure_attribute_absence["alerts"]
    not azure_issue["alerts"]
}

alerts {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
    not azure_attribute_absence["alerts"]
    not azure_issue["alerts"]
}

alerts = false {
    azure_issue["alerts"]
}

alerts_err = "Activity log alerts is not enabled" {
    azure_issue["alerts"]
}

alerts_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Activity log alerts should be enabled",
    "Policy Description": "Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts"
}



# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles


# PR-AZR-CLD-MNT-009

default log_profiles_retention_days = null

azure_attribute_absence["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy
}

azure_attribute_absence["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy.days
}

azure_issue["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) < 365
}

log_profiles_retention_days {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_attribute_absence["log_profiles_retention_days"]
    not azure_issue["log_profiles_retention_days"]
}



log_profiles_retention_days = false {
    azure_issue["log_profiles_retention_days"]
}

log_profiles_retention_days = false {
    azure_attribute_absence["log_profiles_retention_days"]
}

log_profiles_retention_days_err = "Microsoft.Insights/logprofiles resource property retentionPolicy.days missing in the resource" {
    azure_attribute_absence["log_profiles_retention_days"]
} else = "Activity log retention is set to less than 365 days" {
    azure_issue["log_profiles_retention_days"]
}


log_profiles_retention_days_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "activity log retention should be set to 365 days or greater",
    "Policy Description": "Specifies the retention policy for the log. We recommend you set activity log retention for 365 days or greater. (A value of 0 will retain the events indefinitely.)",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles"
}

# PR-AZR-CLD-MNT-010

default log_profiles_retention_enabled = null

azure_attribute_absence["log_profiles_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy
}

azure_attribute_absence["log_profiles_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy.enabled
}

azure_issue_1["log_profiles_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != true
}

log_profiles_retention_enabled {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_attribute_absence["log_profiles_retention_enabled"]
    not azure_issue["log_profiles_retention_enabled"]
}

log_profiles_retention_enabled = false {
    azure_issue["log_profiles_retention_enabled"]
}

log_profiles_retention_enabled = false {
    azure_attribute_absence["log_profiles_retention_enabled"]
}

log_profiles_retention_enabled_err = "Microsoft.Insights/logprofiles property 'retentionPolicy.enabled' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["log_profiles_retention_enabled"]
} else = "Activity log profile retention is currently not enabled" {
    azure_issue["log_profiles_retention_enabled"]
}


log_profiles_retention_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Activity log profile retention should be enabled",
    "Policy Description": "This policy identifies Microsoft.Insights/logprofiles which don't have log retention enabled. Activity Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles"
}


# PR-AZR-CLD-MNT-011

default log_profile_category = null
azure_attribute_absence ["log_profile_category"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.categories
}

no_azure_issue ["log_profile_category"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    array_contains(resource.properties.categories, "write")
    array_contains(resource.properties.categories, "delete")
    array_contains(resource.properties.categories, "action")
}

log_profile_category {
    not azure_attribute_absence["log_profile_category"]
    no_azure_issue["log_profile_category"]
}

log_profile_category = false {
    azure_attribute_absence["log_profile_category"]
}

log_profile_category = false {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not no_azure_issue["log_profile_category"]
}

log_profile_category_err = "microsoft.insights/logprofiles property 'categories' missing in the resource." {
    azure_attribute_absence["log_profile_category"]
} else = "Log profile is not configured to capture all activities" {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not no_azure_issue["log_profile_category"]
}

log_profile_category_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "log profile should be configured to capture all activities",
    "Policy Description": "the categories of the logs. These categories are created as is convenient to the user. Some values are: 'Write', 'Delete', and/or 'Action.' We recommend you configure the log profile to export all activities from the control/management plane.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/logprofiles"
}


#
# PR-AZR-CLD-MNT-014
#

default alerts_to_create_update_sql_server_firewall_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_create_update_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.sql/servers/firewallrules/write";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_create_update_sql_server_firewall_rule_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_sql_server_firewall_rule_exist"]
}

alerts_to_create_update_sql_server_firewall_rule_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-014",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for create or update SQL server firewall rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update SQL server firewall rule does not exist. Creating an activity log alert for Create or update SQL server firewall rule gives insight into SQL server firewall rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-015
#

default alerts_to_create_update_nsg_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_nsg_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_create_update_nsg_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_create_update_nsg_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.network/networksecuritygroups/write";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_create_update_nsg_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_nsg_exist"]
}

alerts_to_create_update_nsg_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-015",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for create or update network security group should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update network security group does not exist. Creating an activity log alert for Create or update network security group gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-016
#

default alerts_to_create_update_nsg_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_create_update_nsg_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.network/networksecuritygroups/securityrules/write";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_create_update_nsg_rule_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_nsg_rule_exist"]
}

alerts_to_create_update_nsg_rule_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-016",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for create or update network security group rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update network security group rule does not exist. Creating an activity log alert for Create or update network security group rule gives insight into network rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-017
#

default alerts_to_create_update_security_solution_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_update_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_create_update_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_create_update_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.security/securitysolutions/write";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_create_update_security_solution_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_create_update_security_solution_exist"]
}

alerts_to_create_update_security_solution_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-017",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for create or update security solution should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create or update security solution does not exist. Creating an activity log alert for Create or update security solution gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-018
#

default alerts_to_create_policy_assignment_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_create_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_create_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_create_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.authorization/policyassignments/write";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_create_policy_assignment_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_create_policy_assignment_exist"]
}

alerts_to_create_policy_assignment_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-018",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for create policy assignment should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Create policy assignment does not exist. Creating an activity log alert for Create policy assignment gives insight into changes done in azure policy - assignments and may reduce the time it takes to detect unsolicited changes.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-019
#

default alerts_to_delete_sql_server_firewall_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_delete_sql_server_firewall_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.sql/servers/firewallrules/delete";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_delete_sql_server_firewall_rule_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_sql_server_firewall_rule_exist"]
}

alerts_to_delete_sql_server_firewall_rule_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-019",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for delete SQL server firewall rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete SQL server firewall rule does not exist. Creating an activity log alert for Delete SQL server firewall rule gives insight into SQL server firewall rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-020
#

default alerts_to_delete_network_security_group_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_network_security_group_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_delete_network_security_group_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_delete_network_security_group_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.network/networksecuritygroups/delete";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_delete_network_security_group_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
    "Policy Code": "PR-AZR-CLD-MNT-020",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for delete network security group should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete network security group does not exist. Creating an activity log alert for the Delete network security group gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-021
#

default alerts_to_delete_network_security_group_rule_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_delete_network_security_group_rule_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.network/networksecuritygroups/securityrules/delete";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_delete_network_security_group_rule_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_network_security_group_rule_exist"]
}

alerts_to_delete_network_security_group_rule_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-021",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for delete network security group rule should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete network security group rule does not exist. Creating an activity log alert for Delete network security group rule gives insight into network rule access changes and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-022
#

default alerts_to_delete_security_solution_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_delete_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_delete_security_solution_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.security/securitysolutions/delete";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_delete_security_solution_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_security_solution_exist"]
}

alerts_to_delete_security_solution_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-022",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for delete security solution should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete security solution does not exist. Creating an activity log alert for Delete security solution gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-023
#

default alerts_to_update_security_policy_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_update_security_policy_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_update_security_policy_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_update_security_policy_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.security/policies/write";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_update_security_policy_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_update_security_policy_exist"]
}

alerts_to_update_security_policy_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-023",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for update security policy should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Update security policy does not exist. Creating an activity log alert for Update security policy gives insight into changes to security policy and may reduce the time it takes to detect suspicious activity.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}


#
# PR-AZR-CLD-MNT-024
#

default alerts_to_delete_policy_assignment_exist = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts_to_delete_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition
}

azure_attribute_absence["alerts_to_delete_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.condition.allOf
}

azure_issue["alerts_to_delete_policy_assignment_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count([c | allOf := resource.properties.condition.allOf[_];
              lower(allOf.field) == "operationname";
              lower(allOf.equals) == "microsoft.authorization/policyassignments/delete";
              not array_element_contains(resource.properties.scopes, "resourceGroups");
              c := 1]) == 0
}

alerts_to_delete_policy_assignment_exist {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
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
} else = "microsoft.insights/activitylogalerts property condition.allOf.field is missing from the resource." {
    azure_attribute_absence["alerts_to_delete_policy_assignment_exist"]
}

alerts_to_delete_policy_assignment_exist_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-024",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Activity log alert for delete policy assignment should exist",
    "Policy Description": "This policy identifies the Azure accounts in which activity log alert for Delete policy assignment does not exist. Creating an activity log alert for Delete policy assignment gives insight into changes done in azure policy - assignments and may reduce the time it takes to detect unsolicited changes.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts?pivots=deployment-language-arm-template"
}