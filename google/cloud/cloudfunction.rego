package rego

#
# PR-GCP-GDF-CF-001
#

default function_security = null

gc_issue["function_security"] {
    # lower(resource.type) == "cloudfunctions.v1.function"
    lower(input.status) == "active"
    lower(input.httpsTrigger.securityLevel) != "secure_always"
}

function_security {
    # lower(input.resources[i].type) == "cloudfunctions.v1.function"
    not gc_issue["function_security"]
}

function_security = false {
    gc_issue["function_security"]
}

function_security_err = "Ensure GCP Cloud Function HTTP trigger is secured" {
    gc_issue["function_security"]
}

function_security_metadata := {
    "Policy Code": "PR-GCP-GDF-CF-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Cloud Function HTTP trigger is secured",
    "Policy Description": "This policy identifies GCP Cloud Functions for which the HTTP trigger is not secured. When you configure HTTP functions to be triggered only with HTTPS, user requests will be redirected to use the HTTPS protocol, which is more secure. It is recommended to set the 'Require HTTPS' for configuring HTTP triggers while deploying your function.",
    "Resource Type": "cloudfunctions.v1.function",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/GoogleCloudPlatform/deploymentmanager-samples/tree/master/google/resource-snippets/cloudfunctions-v1"
}


#
# PR-GCP-GDF-CF-002
#

default function_ingress_allow_all = null

gc_issue["function_ingress_allow_all"] {
    # lower(resource.type) == "cloudfunctions.v1.function"
    lower(input.status) == "active"
    lower(input.ingressSettings) == "allow_all"
}

function_ingress_allow_all {
    # lower(input.resources[i].type) == "cloudfunctions.v1.function"
    not gc_issue["function_ingress_allow_all"]
}

function_ingress_allow_all = false {
    gc_issue["function_ingress_allow_all"]
}

function_ingress_allow_all_err = "Ensure GCP Cloud Function is not configured with overly permissive Ingress setting" {
    gc_issue["function_ingress_allow_all"]
}

function_ingress_allow_all_metadata := {
    "Policy Code": "PR-GCP-GDF-CF-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Cloud Function is not configured with overly permissive Ingress setting",
    "Policy Description": "This policy identifies GCP Cloud Functions that are configured with overly permissive Ingress setting. With overly permissive Ingress setting, all inbound requests to the function are allowed, from both the public and resources within the same project. It is recommended to restrict the traffic from the public and other resources, to get better network-based access control and allow traffic from VPC networks in the same project or traffic through the Cloud Load Balancer.",
    "Resource Type": "cloudfunctions.v1.function",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/GoogleCloudPlatform/deploymentmanager-samples/tree/master/google/resource-snippets/cloudfunctions-v1"
}


#
# PR-GCP-GDF-CF-003
#

default function_vpc_connector = null

gc_issue["function_vpc_connector"] {
    # lower(resource.type) == "cloudfunctions.v1.function"
    lower(input.status) == "active"
    not input.vpcConnector
}

gc_issue["function_vpc_connector"] {
    # lower(resource.type) == "cloudfunctions.v1.function"
    lower(input.status) == "active"
    count(input.vpcConnector) == 0
}

function_vpc_connector {
    # lower(input.resources[i].type) == "cloudfunctions.v1.function"
    not gc_issue["function_vpc_connector"]
}

function_vpc_connector = false {
    gc_issue["function_vpc_connector"]
}

function_vpc_connector_err = "Ensure GCP Cloud Function is enabled with VPC connector" {
    gc_issue["function_vpc_connector"]
}

function_vpc_connector_metadata := {
    "Policy Code": "PR-GCP-GDF-CF-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Cloud Function is enabled with VPC connector",
    "Policy Description": "This policy identifies GCP Cloud Functions that are not configured with a VPC connector. VPC connector helps function to connect to a resource inside a VPC in the same project. Setting up the VPC connector allows you to set up a secure perimeter to guard against data exfiltration and prevent functions from accidentally sending any data to unwanted destinations. It is recommended to configure the GCP Cloud Function with a VPC connector.\n\nNote: For the Cloud Functions function to access the public traffic with Serverless VPC connector, you have to introduce Cloud NAT.\nLink: https://cloud.google.com/functions/docs/networking/network-settings#route-egress-to-vpc",
    "Resource Type": "cloudfunctions.v1.function",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/GoogleCloudPlatform/deploymentmanager-samples/tree/master/google/resource-snippets/cloudfunctions-v1"
}
