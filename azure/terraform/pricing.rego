package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_security_center_subscription_pricing

#
# PR-AZR-0091-TRF
#

default pricing = null

azure_attribute_absence["pricing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier
}

azure_issue["pricing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.tier) != "standard"
}

pricing {
    lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
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
    "Policy Code": "PR-AZR-0091-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Standard pricing tier is not selected in Security Center",
    "Policy Description": "Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.",
    "Compliance": ["CIS","ISO 27001"],
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_security_center_subscription_pricing"
}
