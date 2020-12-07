package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_security_center_contact

#
# Security contact emails is not set in Security Center (296)
#

default securitycontacts = null

azure_attribute_absence["securitycontacts"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.email
}

azure_issue["securitycontacts"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    re_match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$", resource.properties.email) == false
}

securitycontacts {
    lower(input.json.resources[_].type) == "azurerm_security_center_contact"
    not azure_issue["securitycontacts"]
    not azure_attribute_absence["securitycontacts"]
}

securitycontacts = false {
    azure_issue["securitycontacts"]
}

securitycontacts = false {
    azure_attribute_absence["securitycontacts"]
}

securitycontacts_err = "Security contact emails is not set in Security Center" {
    azure_issue["securitycontacts"]
}

securitycontacts_miss_err = "Security Contacts attribute mail missing in the resource" {
    azure_attribute_absence["securitycontacts"]
}
