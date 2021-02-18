#
# PR-AZR-0071
#

package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-05-01-preview/diagnosticsettings

rulepass = false {
    count(input.properties.logs) == 0
}

rulepass = false {
    input.properties.logs[_].enabled == false
}
