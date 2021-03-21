#
# PR-GCP-0093
#

package rule
default rulepass = false

# VM Instances without any Label information
rulepass = true {                                      
    lower(input.type) == "compute.v1.instance"
   count(labels) == 1
}

# $.labels[*] == null
labels["label"] {
   not input.labels
}
