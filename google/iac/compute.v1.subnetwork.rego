package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks

#
# PR-GCP-0074-GDF
#

default vpc_flow_logs = null

gc_issue["vpc_flow_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.subnetwork"
    not resource.properties.enableFlowLogs
}

vpc_flow_logs {
    lower(input.resources[_].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_flow_logs"]
}

vpc_flow_logs = false {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_err = "GCP VPC Flow logs for the subnet is set to Off" {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_metadata := {
    "Policy Code": "PR-GCP-0074-GDF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VPC Flow logs for the subnet is set to Off",
    "Policy Description": "This policy identifies the subnets in VPC Network which have Flow logs disabled. It enables to capture information about the IP traffic going to and from network interfaces in VPC Subnets.",
    "Resource Type": "compute.v1.subnetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
}

#
# PR-GCP-0075-GDF
#

default vpc_private_ip_google = null

gc_issue["vpc_private_ip_google"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.subnetwork"
    not resource.properties.privateIpGoogleAccess
}

vpc_private_ip_google {
    lower(input.resources[_].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google = false {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_err = "GCP VPC Network subnets have Private Google access disabled" {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_metadata := {
    "Policy Code": "PR-GCP-0075-GDF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VPC Network subnets have Private Google access disabled",
    "Policy Description": "This policy identifies GCP VPC Network subnets have disabled Private Google access. Private Google access enables virtual machine instances on a subnet to reach Google APIs and services using an internal IP address rather than an external IP address. Internal (private) IP addresses are internal to Google Cloud Platform and are not routable or reachable over the Internet. You can use Private Google access to allow VMs without Internet access to reach Google APIs, services, and properties that are accessible over HTTP/HTTPS.",
    "Resource Type": "compute.v1.subnetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
}
