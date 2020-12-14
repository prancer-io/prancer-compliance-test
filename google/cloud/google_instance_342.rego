#
# PR-GCP-0072
#

package rule
default rulepass = false

# metadata.items[*].key contains serial-port-enable and metadata.items[*].value contains true'

rulepass = true {                                      
   count(metadata) == 1
}

# nodePools[*].config.serviceAccount contains default
metadata["input.items"] {
   input.metadata.items[_].key = "serial-port-enable"
   input.metadata.items[_].value = "true"

}
