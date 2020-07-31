package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/instances

#
# Id: 340
#

default vm_ip_forward = null

gc_issue["vm_ip_forward"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.instance"
    resource.properties.canIpForward
}

vm_ip_forward {
    lower(input.json.resources[_].type) == "compute.v1.instance"
    not gc_issue["vm_ip_forward"]
}

vm_ip_forward = false {
    gc_issue["vm_ip_forward"]
}

vm_ip_forward_err = "GCP VM instances have IP forwarding enabled" {
    gc_issue["vm_ip_forward"]
}
