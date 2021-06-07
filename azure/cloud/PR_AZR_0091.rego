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

metadata := {
    "Policy Code": "PR-AZR-0091",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Standard pricing tier is not selected in Security Center",
    "Policy Description": "Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.",
    "Resource Type": "microsoft.security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings"
}
