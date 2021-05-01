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
