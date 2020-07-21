package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings

#
# Standard pricing tier is not selected in Security Center (300)
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
