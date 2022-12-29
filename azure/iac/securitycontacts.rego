package rule

# "apiVersion": "2020-01-01-preview"

# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template
#
# PR-AZR-ARM-ASC-002
#

default securitycontacts = null

azure_attribute_absence["securitycontacts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.emails
}

azure_issue["securitycontacts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    # re_match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$", resource.properties.email) == false
    count(resource.properties.emails) == 0
}

securitycontacts {
    lower(input.resources[_].type) == "microsoft.security/securitycontacts"
    not azure_attribute_absence["securitycontacts"]
    not azure_issue["securitycontacts"]
}

securitycontacts = false {
    azure_issue["securitycontacts"]
}

securitycontacts = false {
    azure_attribute_absence["securitycontacts"]
}

securitycontacts_err = "Security Center currently does not have any security contact email configured" {
    azure_issue["securitycontacts"]
} else = "Security Center security contacts property 'emails' is missing from the resource" {
    azure_attribute_absence["securitycontacts"]
}

securitycontacts_metadata := {
    "Policy Code": "PR-AZR-ARM-ASC-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Security Center should have security contact emails configured to get notifications",
    "Policy Description": "Setting a valid email address in Security contact emails will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "microsoft.security/securitycontacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts"
}


# 
# PR-AZR-ARM-ASC-003
#

default alert_notifications = null

azure_attribute_absence["alert_notifications"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.alertNotifications
}

azure_attribute_absence["alert_notifications"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.alertNotifications.state
}

azure_issue["alert_notifications"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    lower(resource.properties.alertNotifications.state) != "on"
}

alert_notifications {
    lower(input.resources[_].type) == "microsoft.security/securitycontacts"
    not azure_attribute_absence["alert_notifications"]
    not azure_issue["alert_notifications"]
}

alert_notifications = false {
    azure_issue["alert_notifications"]
}

alert_notifications = false {
    azure_attribute_absence["alert_notifications"]
}

alert_notifications_err = "microsoft.security/securitycontacts resource property alertNotifications.state is missing from the resource" {
    azure_attribute_absence["securitycontacts"]
} else = "Send email notification for alerts is not enabled" {
    azure_issue["alert_notifications"]
}

alert_notifications_metadata := {
    "Policy Code": "PR-AZR-ARM-ASC-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Security Center shoud send security alerts notifications to the security contact",
    "Policy Description": "Setting the security alert Send email notification for alerts to On ensures that emails are sent from Microsoft if their security team determines a potential security breach has taken place.",
    "Resource Type": "microsoft.security/securitycontacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts"
}


# PR-AZR-ARM-ASC-005
#

default securitycontacts_alerts_to_admins_enabled = null

azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.notificationsByRole
}

azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.notificationsByRole.state
}

azure_issue["securitycontacts_alerts_to_admins_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    lower(resource.properties.notificationsByRole.state) != "on"
}

securitycontacts_alerts_to_admins_enabled {
    lower(input.resources[_].type) == "microsoft.security/securitycontacts"
    not azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"]
    not azure_issue["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled = false {
    azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled = false {
    azure_issue["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled_err = "Security Center currently not configured to send security alerts notifications to subscription admins" {
    azure_issue["securitycontacts_alerts_to_admins_enabled"]
} else = "microsoft.security/securitycontacts property 'notificationsByRole.state' need to be exist. Its missing from the resource. Please set 'On' as value after property addition."  {
    azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled_metadata := {
    "Policy Code": "PR-AZR-ARM-ASC-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Security Center shoud send security alerts notifications to subscription admins",
    "Policy Description": "This policy will identify security centers which dont have configuration enabled to send security alerts notifications to subscription admins and alert if missing.",
    "Resource Type": "microsoft.security/securitycontacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts"
}