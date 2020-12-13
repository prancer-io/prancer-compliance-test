package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_security_center_subscription_pricing

#
# PR-AZR-0091-TRF
#

default pricing = null

azure_attribute_absence["pricing"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier
}

azure_issue["pricing"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.tier) != "standard"
}

pricing {
    lower(input.json.resources[_].type) == "azurerm_security_center_subscription_pricing"
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
