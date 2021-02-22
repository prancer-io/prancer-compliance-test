#
# PR-AZR-0091
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings

rulepass {        
	input.type = "Microsoft.Security/pricings"
   lower(input.properties.pricingTier) == "standard"
}
