package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks

#
# Id: 344
#

default vpc_flow_logs = null

gc_issue["vpc_flow_logs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.subnetwork"
    not resource.properties.enableFlowLogs
}

vpc_flow_logs {
    lower(input.json.resources[_].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_flow_logs"]
}

vpc_flow_logs = false {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_err = "GCP VPC Flow logs for the subnet is set to Off" {
    gc_issue["vpc_flow_logs"]
}

#
# Id: 345
#

default vpc_private_ip_google = null

gc_issue["vpc_private_ip_google"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.subnetwork"
    not resource.properties.privateIpGoogleAccess
}

vpc_private_ip_google {
    lower(input.json.resources[_].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google = false {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_err = "GCP VPC Network subnets have Private Google access disabled" {
    gc_issue["vpc_private_ip_google"]
}
