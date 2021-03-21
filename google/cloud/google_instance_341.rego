#
# PR-GCP-0071
#

package rule
default rulepass = false

# GCP VM instances have block project-wide SSH keys feature disabled
# 'metadata.items[*].key does not contain block-project-ssh-keys'

rulepass = true {                                      
    lower(input.type) == "compute.v1.instance"
   count(blocksshkey) == 0
}

blocksshkey[input.id] {
   input.metadata.items[_].key="block-project-ssh-keys"
}