#
# PR-AZR-0005
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks

rulepass {
    substring(lower(input.properties.serviceUri), 0, 6) == "https:"
}
