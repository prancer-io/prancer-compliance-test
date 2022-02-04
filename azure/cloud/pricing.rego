package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings

#
# PR-AZR-CLD-ASC-001
#

default pricing = null

azure_attribute_absence["pricing"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    not resource.properties.pricingTier
}

azure_issue["pricing"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.properties.pricingTier) != "standard"
}

pricing {
    lower(input.resources[_].type) == "microsoft.security/pricings"
    not azure_issue["pricing"]
    not azure_attribute_absence["pricing"]
}

pricing = false {
    azure_issue["pricing"]
}

pricing = false {
    azure_attribute_absence["pricing"]
}

pricing_err = "Azure Security Center currently dont have 'standard' pricing tier configured" {
    azure_issue["pricing"]
} else = "Azure Security Center property 'pricingTier' is missing from the resource" {
    azure_attribute_absence["pricing"]
}

pricing_metadata := {
    "Policy Code": "PR-AZR-CLD-ASC-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Security Center should have pricing tier configured to 'standard'",
    "Policy Description": "Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.",
    "Resource Type": "microsoft.security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings"
}
