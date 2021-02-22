#
# PR-AZR-0058
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments

rulepass {
   input.type == "Microsoft.Sql/servers/databases/vulnerabilityAssessments"
   input.properties.recurringScans.isEnabled == true
}
