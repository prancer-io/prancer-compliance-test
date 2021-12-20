package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings

#
# PR-AZR-ASC-001
#

default pricing = null

azure_attribute_absence["pricing"] {
    not input.properties.pricingTier
}

azure_issue["pricing"] {
    lower(input.properties.pricingTier) != "standard"
}

pricing {
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
    "Policy Code": "PR-AZR-ASC-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Security Center should have pricing tier configured to 'standard'",
    "Policy Description": "Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.",
    "Resource Type": "microsoft.security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings"
}
