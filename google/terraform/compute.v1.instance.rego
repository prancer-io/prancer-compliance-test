package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/instances

#
# PR-GCP-0070-TRF
#

default vm_ip_forward = null

gc_issue["vm_ip_forward"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    resource.properties.can_ip_forward
}

vm_ip_forward {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_ip_forward"]
}

vm_ip_forward = false {
    gc_issue["vm_ip_forward"]
}

vm_ip_forward_err = "GCP VM instances have IP forwarding enabled" {
    gc_issue["vm_ip_forward"]
}

vm_ip_forward_metadata := {
    "Policy Code": "PR-GCP-0070-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP VM instances have IP forwarding enabled",
    "Policy Description": "This policy identifies VM instances have IP forwarding enabled. IP Forwarding could open unintended and undesirable communication paths and allows VM instances to send and receive packets with the non-matching destination or source IPs. To enable source and destination IP match check, disable the IP Forwarding.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-0071-TRF
#

default vm_block_project_ssh_keys = null

gc_issue["vm_block_project_ssh_keys"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not resource.properties.metadata["block-project-ssh-keys"]
}

vm_block_project_ssh_keys {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys = false {
    gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys_err = "GCP VM instances have block project-wide SSH keys feature disabled" {
    gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys_metadata := {
    "Policy Code": "PR-GCP-0071-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP VM instances have block project-wide SSH keys feature disabled",
    "Policy Description": "This policy identifies VM instances which have block project-wide SSH keys feature disabled. Project-wide SSH keys are stored in Compute/Project-metadata. Project-wide SSH keys can be used to login into all the instances within a project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within a project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-0072-TRF
#

default vm_serial_port = null

gc_issue["vm_serial_port"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    resource.properties.metadata["serial-port-enable"] == true
}

vm_serial_port {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_serial_port"]
}

vm_serial_port = false {
    gc_issue["vm_serial_port"]
}

vm_serial_port_err = "GCP VM instances have serial port access enabled" {
    gc_issue["vm_serial_port"]
}

vm_serial_port_metadata := {
    "Policy Code": "PR-GCP-0072-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP VM instances have serial port access enabled",
    "Policy Description": "This policy identifies VM instances which have serial port access enabled. Interacting with a serial port is often referred to as the serial console. The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. So it is recommended to keep interactive serial console support disabled.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-0091-TRF
#

default vm_pre_emptible = null

gc_issue["vm_pre_emptible"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    resource.properties.scheduling.preemptible == true
}

vm_pre_emptible {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_pre_emptible"]
}

vm_pre_emptible = false {
    gc_issue["vm_pre_emptible"]
}

vm_pre_emptible_err = "VM Instances enabled with Pre-Emptible termination" {
    gc_issue["vm_pre_emptible"]
}

vm_pre_emptible_metadata := {
    "Policy Code": "PR-GCP-0091-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "VM Instances enabled with Pre-Emptible termination",
    "Policy Description": "Checks to verify if any VM instance is initiated with the flag 'Pre-Emptible termination' set to True. Setting this instance to True implies that this VM instance will shut down within 24 hours or can also be terminated by a Service Engine when high demand is encountered. While this might save costs, it can also lead to unexpected loss of service when the VM instance is terminated.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-0092-TRF
#

default vm_metadata = null

gc_issue["vm_metadata"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not resource.properties.metadata
}

gc_issue["vm_metadata"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    count(resource.properties.metadata) == 0
}

vm_metadata {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_metadata"]
}

vm_metadata = false {
    gc_issue["vm_metadata"]
}

vm_metadata_err = "VM Instances without any Custom metadata information" {
    gc_issue["vm_metadata"]
}

vm_metadata_metadata := {
    "Policy Code": "PR-GCP-0092-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "VM Instances without any Custom metadata information",
    "Policy Description": "VM instance does not have any Custom metadata. Custom metadata can be used for easy identification and searches.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-0093-TRF
#

default vm_no_labels = null

gc_issue["vm_no_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not resource.properties.labels
}

gc_issue["vm_no_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    count(resource.properties.labels) == 0
}

vm_no_labels {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_no_labels"]
}

vm_no_labels = false {
    gc_issue["vm_no_labels"]
}

vm_no_labels_err = "VM Instances without any Label information" {
    gc_issue["vm_no_labels"]
}

vm_no_labels_metadata := {
    "Policy Code": "PR-GCP-0093-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "VM Instances without any Label information",
    "Policy Description": "VM instance does not have any Labels. Labels can be used for easy identification and searches.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-0094-TRF
#

default vm_info = null

gc_issue["vm_info"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not resource.properties.labels
}

gc_issue["vm_info"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    count(resource.properties.labels) == 0
}

gc_issue["vm_info"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not resource.properties.metadata
}

gc_issue["vm_info"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    count(resource.properties.metadata) == 0
}

gc_issue["vm_info"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not resource.properties.zone
}

vm_info {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_info"]
}

vm_info = false {
    gc_issue["vm_info"]
}

vm_info_err = "VM instances without metadata, zone or label information" {
    gc_issue["vm_info"]
}

vm_info_metadata := {
    "Policy Code": "PR-GCP-0094-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "VM instances without metadata, zone or label information",
    "Policy Description": "Checks to ensure that VM instances have proper metadata, zone and label information tags. These tags can be used for easier identification and searches.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}
