#
# PR-AZR-0019
#

package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-05-01-preview/diagnosticsettings

rulepass = false {
    input.type == "Microsoft.Insights/diagnosticSettings"
    count(input.properties.logs) == 0
}

rulepass = false {
    input.type == "Microsoft.Insights/diagnosticSettings"
    input.properties.logs[_].enabled == false
}
