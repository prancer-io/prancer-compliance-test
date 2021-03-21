#
# PR-GCP-0094
#

package rule
default rulepass = false

# VM instances without metadata, zone or label information

rulepass = true {                                      
    lower(input.type) == "compute.v1.instance"
   count(scheduling) >= 1
}

# '$.labels equals null or 
scheduling["labels"] {
   not input.labels
}

# $.zone equals null or 
scheduling["zone"] {
   input.zone
}

# $.metadata equals null'
scheduling["metadata"] {
   not input.metadata
}

