package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks

#
# PR-GCP-0074-TRF
#

default vpc_flow_logs = null

gc_issue["vpc_flow_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_subnetwork"
    count(resource.properties.log_config) == 0
}

vpc_flow_logs {
    lower(input.resources[_].type) == "google_compute_subnetwork"
    not gc_issue["vpc_flow_logs"]
}

vpc_flow_logs = false {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_err = "GCP VPC Flow logs for the subnet is set to Off" {
    gc_issue["vpc_flow_logs"]
}

#
# PR-GCP-0075-TRF
#

default vpc_private_ip_google = null

gc_issue["vpc_private_ip_google"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_subnetwork"
    not resource.properties.private_ip_google_access
}

vpc_private_ip_google {
    lower(input.resources[_].type) == "google_compute_subnetwork"
    not gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google = false {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_err = "GCP VPC Network subnets have Private Google access disabled" {
    gc_issue["vpc_private_ip_google"]
}
