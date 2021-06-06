package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings

#
# PR-AZR-0091-ARM
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

pricing_err = "Standard pricing tier is not selected in Security Center" {
    azure_issue["pricing"]
}

pricing_miss_err = "Pricing attribute pricingTier missing in the resource" {
    azure_attribute_absence["pricing"]
}

pricing_metadata := {
    "Policy Code": "PR-AZR-0091-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Standard pricing tier is not selected in Security Center",
    "Policy Description": "Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.",
    "Resource Type": "microsoft.security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings"
}
