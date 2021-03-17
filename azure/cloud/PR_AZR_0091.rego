#
# PR-AZR-0091
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings

rulepass {
    lower(input.type) == "microsoft.security/pricings"
    lower(input.properties.pricingTier) == "standard"
}
