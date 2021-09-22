package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts

#
# PR-AZR-0087-ARM
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
    re_match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$", resource.properties.emails) == false
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

securitycontacts_err = "Security Center currently does not have any valid security contact email configured" {
    azure_issue["securitycontacts"]
}

securitycontacts_miss_err = "Security Center security contacts property 'emails' is missing from the resource" {
    azure_attribute_absence["securitycontacts"]
}

securitycontacts_metadata := {
    "Policy Code": "PR-AZR-0087-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Security Center shoud have security contact emails configured to get notifications",
    "Policy Description": "Setting a valid email address in Security contact emails will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "microsoft.security/securitycontacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts"
}




#
# PR-AZR-0143-ARM
#

default alert_notifications = null

azure_attribute_absence["alert_notifications"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.alertNotifications
}

azure_issue["alert_notifications"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    lower(resource.properties.alertNotifications) != "on"
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

alert_notifications_err = "microsoft.security/securitycontacts resource property alertNotifications missing in the resource" {
    azure_attribute_absence["securitycontacts"]
} else = "Send email notification for alerts is not enabled" {
    azure_issue["alert_notifications"]
}

alert_notifications_metadata := {
    "Policy Code": "PR-AZR-0143-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Send email notification should be enabled",
    "Policy Description": "Setting the security alert Send email notification for alerts to On ensures that emails are sent from Microsoft if their security team determines a potential security breach has taken place.",
    "Resource Type": "microsoft.security/securitycontacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts"
}