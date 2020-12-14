package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts

#
# PR-AZR-0087-ARM
#

default securitycontacts = null

azure_attribute_absence["securitycontacts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.email
}

azure_issue["securitycontacts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    re_match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$", resource.properties.email) == false
}

securitycontacts {
    lower(input.resources[_].type) == "microsoft.security/securitycontacts"
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
