package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_security_center_contact
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact
#
# PR-AZR-TRF-ASC-002
#

default securitycontacts = null

azure_attribute_absence["securitycontacts"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.email
}

azure_issue["securitycontacts"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    re_match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$", resource.properties.email) == false
}

securitycontacts {
    lower(input.resources[_].type) == "azurerm_security_center_contact"
    not azure_attribute_absence["securitycontacts"]
    not azure_issue["securitycontacts"]
}

securitycontacts = false {
    azure_attribute_absence["securitycontacts"]
}

securitycontacts = false {
    azure_issue["securitycontacts"]
}

securitycontacts_err = "azurerm_security_center_contact property 'email' need to be exist. Its missing from the resource. Please set a valid email address as value after property addition." {
    azure_attribute_absence["securitycontacts"]
} else = "Security Center currently does not have any valid security contact email configured"  {
    azure_issue["securitycontacts"]
}

securitycontacts_metadata := {
    "Policy Code": "PR-AZR-TRF-ASC-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Security Center shoud have security contact email configured to get notifications",
    "Policy Description": "Setting a valid email address in Security contact emails will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "azurerm_security_center_contact",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact"
}


#
# PR-AZR-TRF-ASC-004
#

default securitycontacts_phone = null

azure_attribute_absence["securitycontacts_phone"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.phone
}

azure_issue["securitycontacts_phone"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    count(resource.properties.phone) == 0
}

securitycontacts_phone {
    lower(input.resources[_].type) == "azurerm_security_center_contact"
    not azure_attribute_absence["securitycontacts"]
    not azure_issue["securitycontacts"]
}

securitycontacts_phone = false {
    azure_attribute_absence["securitycontacts"]
}

securitycontacts_phone = false {
    azure_issue["securitycontacts"]
}

securitycontacts_phone_err = "azurerm_security_center_contact property 'phone' need to be exist. Its missing from the resource. Please set a valid phone number as value after property addition." {
    azure_attribute_absence["securitycontacts_phone"]
} else = "Security Center currently does not have any valid security contact phone number configured"  {
    azure_issue["securitycontacts_phone"]
}

securitycontacts_phone_metadata := {
    "Policy Code": "PR-AZR-TRF-ASC-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Security Center shoud have security contact phone number configured to get notifications",
    "Policy Description": "Setting a valid phone number in Security contact phone will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "azurerm_security_center_contact",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact"
}


#
# PR-AZR-TRF-ASC-003
#

default securitycontacts_alert_notifications_enabled = null

azure_attribute_absence["securitycontacts_alert_notifications_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.alert_notifications
}

azure_issue["securitycontacts_alert_notifications_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    resource.properties.alert_notifications != true
}

securitycontacts_alert_notifications_enabled {
    lower(input.resources[_].type) == "azurerm_security_center_contact"
    not azure_attribute_absence["securitycontacts_alert_notifications_enabled"]
    not azure_issue["securitycontacts_alert_notifications_enabled"]
}

securitycontacts_alert_notifications_enabled = false {
    azure_attribute_absence["securitycontacts_alert_notifications_enabled"]
}

securitycontacts_alert_notifications_enabled = false {
    azure_issue["securitycontacts_alert_notifications_enabled"]
}

securitycontacts_alert_notifications_enabled_err = "azurerm_security_center_contact property 'alert_notifications' need to be exist. Its missing from the resource. Please set 'true' as value after property addition." {
    azure_attribute_absence["securitycontacts_alert_notifications_enabled"]
} else = "Security Center currently not configured to send security alerts notifications to the security contact."  {
    azure_issue["securitycontacts_alert_notifications_enabled"]
}

securitycontacts_alert_notifications_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ASC-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Security Center shoud send security alerts notifications to the security contact",
    "Policy Description": "This policy will identify security centers which dont have configuration enabled to send security alerts notifications to the security contact and alert if missing.",
    "Resource Type": "azurerm_security_center_contact",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact"
}


#
# PR-AZR-TRF-ASC-005
#

default securitycontacts_alerts_to_admins_enabled = null

azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.alerts_to_admins
}

azure_issue["securitycontacts_alerts_to_admins_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    resource.properties.alerts_to_admins != true
}

securitycontacts_alerts_to_admins_enabled {
    lower(input.resources[_].type) == "azurerm_security_center_contact"
    not azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"]
    not azure_issue["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled = false {
    azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled = false {
    azure_issue["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled_err = "azurerm_security_center_contact property 'alerts_to_admins' need to be exist. Its missing from the resource. Please set 'true' as value after property addition." {
    azure_attribute_absence["securitycontacts_alerts_to_admins_enabled"]
} else = "Security Center currently not configured to send security alerts notifications to subscription admins"  {
    azure_issue["securitycontacts_alerts_to_admins_enabled"]
}

securitycontacts_alerts_to_admins_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ASC-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Security Center shoud send security alerts notifications to subscription admins",
    "Policy Description": "This policy will identify security centers which dont have configuration enabled to send security alerts notifications to subscription admins and alert if missing.",
    "Resource Type": "azurerm_security_center_contact",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact"
}