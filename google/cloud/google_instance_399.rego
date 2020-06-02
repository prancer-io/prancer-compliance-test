package rule
default rulepass = false

# VM instances without metadata, zone or label information

rulepass = true {                                      
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

