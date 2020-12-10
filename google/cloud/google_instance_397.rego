#
# PR-GCP-0092
#

package rule
default rulepass = false

# VM Instances without any custom metadata information
rulepass = true {                                      
   count(metadata) == 1
}

# $.metadata.items[*] == null'
metadata["metadata_items"] {
   not input.metadata
}
