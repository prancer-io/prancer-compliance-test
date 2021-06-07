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

metadata := {
    "Policy Code": "PR-GCP-0071",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP VM instances have block project-wide SSH keys feature disabled",
    "Policy Description": "This policy identifies VM instances which have block project-wide SSH keys feature disabled. Project-wide SSH keys are stored in Compute/Project-metadata. Project-wide SSH keys can be used to login into all the instances within a project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within a project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
