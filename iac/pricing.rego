package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings

#
# Standard pricing tier is not selected in Security Center (300)
#

default pricing = null

pricing {
    lower(input.type) == "microsoft.security/pricings"
    lower(input.properties.pricingTier) == "standard"
}

pricing = false {
    lower(input.type) == "microsoft.security/pricings"
    lower(input.properties.pricingTier) != "standard"
}

pricing_err = "Standard pricing tier is not selected in Security Center" {
    pricing == false
}
