#
# PR-AZR-0005
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks

rulepass {
    lower(input.type) == "microsoft.containerregistry/registries/webhooks"
    substring(lower(input.properties.serviceUri), 0, 6) == "https:"
}

metadata := {
    "Policy Code": "PR-AZR-0005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure ACR HTTPS not enabled for webhook",
    "Policy Description": "Ensure you send container registry webhooks only to a HTTPS endpoint. This policy checks your container registry webhooks and alerts if it finds a URI with HTTP.",
    "Compliance": [],
    "Resource Type": "microsoft.containerregistry/registries/webhooks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks"
}
