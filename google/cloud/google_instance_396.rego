#
# PR-GCP-0091
#

package rule
default rulepass = false

# VM Instances enabled with Pre-Emptible termination
rulepass = true {                                      
    lower(input.type) == "compute.v1.instance"
   count(scheduling) == 1
}

# '$.scheduling.preemptible == true'
scheduling["scheduling_preemptible"] {
   input.scheduling.preemptible = true
}
