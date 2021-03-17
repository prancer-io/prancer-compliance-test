#
# PR-AZR-0051
#

package rule
default rulepass = false

# Azure Network Watcher Network Security Group (NSG) flow logs retention is less than 90 days
# If NSG flow logs retention is 90 more than 90 days test will pass

rulepass = true {
   lower(input.type) == "microsoft.network/networkwatchers"
   count(nsg_retentionPolicy) == 2
}

# properties.retentionPolicy.enabled
# properties.retentionPolicy.days >= 90

nsg_retentionPolicy["retentionPolicy_enabled"] {
   input.properties.retentionPolicy.enabled == true
}

nsg_retentionPolicy["retentionPolicy_day_90"] {
   input.properties.retentionPolicy.days >= 90
}
