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
