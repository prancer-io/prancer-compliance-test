package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


# https://cloud.google.com/compute/docs/reference/rest/v1/instances

#
# PR-GCP-TRF-INST-001
#

default vm_ip_forward = null

gc_issue["vm_ip_forward"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not startswith(lower(resource.properties.name), "gke-")
    resource.properties.can_ip_forward
}

gc_issue["vm_ip_forward"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    resource.properties.can_ip_forward
    startswith(lower(resource.properties.name), "gke-")
    not has_property(resource.properties.boot_disk[_].initialize_params , "labels")
}

gc_issue["vm_ip_forward"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    resource.properties.can_ip_forward
    startswith(lower(resource.properties.name), "gke-")
    not resource.properties.boot_disk[_].initialize_params.labels
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
    "Policy Code": "PR-GCP-TRF-INST-001",
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
# PR-GCP-TRF-INST-002
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
    "Policy Code": "PR-GCP-TRF-INST-002",
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
# PR-GCP-TRF-INST-003
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
    "Policy Code": "PR-GCP-TRF-INST-003",
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
# PR-GCP-TRF-INST-004
#

default vm_pre_emptible = null

gc_attribute_absence["vm_pre_emptible"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    not resource.properties.scheduling
}

gc_attribute_absence["vm_pre_emptible"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    count(resource.properties.scheduling) == 0
}

gc_issue["vm_pre_emptible"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_instance"
    scheduling := resource.properties.scheduling[_]
    scheduling.preemptible == true
}

vm_pre_emptible {
    lower(input.resources[_].type) == "google_compute_instance"
    not gc_issue["vm_pre_emptible"]
    not gc_attribute_absence["vm_pre_emptible"]
}

vm_pre_emptible = false {
    gc_issue["vm_pre_emptible"]
} else = false {
    gc_attribute_absence["vm_pre_emptible"]
}

vm_pre_emptible_err = "VM Instances enabled with Pre-Emptible termination" {
    gc_issue["vm_pre_emptible"]
} else = "VM Instances attribute scheduling missing in the resource" {
    gc_attribute_absence["vm_pre_emptible"]
}

vm_pre_emptible_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-004",
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
# PR-GCP-TRF-INST-005
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
    "Policy Code": "PR-GCP-TRF-INST-005",
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
# PR-GCP-TRF-INST-006
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
    "Policy Code": "PR-GCP-TRF-INST-006",
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
# PR-GCP-TRF-INST-007
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
    "Policy Code": "PR-GCP-TRF-INST-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "VM instances without metadata, zone or label information",
    "Policy Description": "Checks to ensure that VM instances have proper metadata, zone and label information tags. These tags can be used for easier identification and searches.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-TRF-INST-011
#

default compute_configure_default_service = null

gc_issue["compute_configure_default_service"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_instance"
    not startswith(lower(resource.properties.name), "gke-")
    service_account := resource.properties.service_account[_]
    contains(lower(service_account.email), "compute@developer.gserviceaccount.com")
}

compute_configure_default_service {
    lower(input.resources[i].type) == "google_compute_instance"
    not gc_issue["compute_configure_default_service"]
}

compute_configure_default_service = false {
    gc_issue["compute_configure_default_service"]
}

compute_configure_default_service_err = "Ensure GCP VM instance not configured with default service account" {
    gc_issue["compute_configure_default_service"]
}

compute_configure_default_service_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP VM instance not configured with default service account",
    "Policy Description": "This policy identifies GCP VM instances configured with the default service account. To defend against privilege escalations if your VM is compromised and prevent an attacker from gaining access to all of your project, it is recommended to not use the default Compute Engine service account because it has the Editor role on the project.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-TRF-INST-012
#

default compute_default_service_full_access = null

gc_issue["compute_default_service_full_access"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_instance"
    not startswith(lower(resource.properties.name), "gke-")
    service_account := resource.properties.service_account[_]
    contains(lower(service_account.email), "compute@developer.gserviceaccount.com")
    lower(service_account.scopes) == "https://www.googleapis.com/auth/cloud-platform"
}

compute_default_service_full_access {
    lower(input.resources[i].type) == "google_compute_instance"
    not gc_issue["compute_default_service_full_access"]
}

compute_default_service_full_access = false {
    gc_issue["compute_default_service_full_access"]
}

compute_default_service_full_access_err = "Ensure GCP VM instance not using a default service account with full access to all Cloud APIs" {
    gc_issue["compute_default_service_full_access"]
}

compute_default_service_full_access_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP VM instance not using a default service account with full access to all Cloud APIs",
    "Policy Description": "This policy identifies the GCP VM instances which are using a default service account with full access to all Cloud APIs. To compliant with the principle of least privileges and prevent potential privilege escalation it is recommended that instances are not assigned to default service account 'Compute Engine default service account' with scope 'Allow full access to all Cloud APIs'.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-TRF-INST-013
#

default compute_shielded_vm = null

gc_issue["compute_shielded_vm"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_instance"
    not startswith(lower(resource.properties.name), "gke-")
    shielded_instance_config := resource.properties.shielded_instance_config[_]
    not shielded_instance_config.enable_vtpm
}

gc_issue["compute_shielded_vm"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_instance"
    not startswith(lower(resource.properties.name), "gke-")
    shielded_instance_config := resource.properties.shielded_instance_config[_]
    not shielded_instance_config.enable_integrity_monitoring
}

compute_shielded_vm {
    lower(input.resources[i].type) == "google_compute_instance"
    not gc_issue["compute_shielded_vm"]
}

compute_shielded_vm = false {
    gc_issue["compute_shielded_vm"]
}

compute_shielded_vm_err = "Ensure GCP VM instance with Shielded VM features enabled" {
    gc_issue["compute_shielded_vm"]
}

compute_shielded_vm_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP VM instance with Shielded VM features enabled",
    "Policy Description": "This policy identifies VM instances which have Shielded VM features disabled. Shielded VMs are virtual machines (VMs) on Google Cloud Platform hardened by a set of security controls that help defend against rootkits and bootkits. Shielded VM's verifiable integrity is achieved through the use of Secure Boot, virtual trusted platform module (vTPM)-enabled Measured Boot, and integrity monitoring. Shielded VM instances run firmware which is signed and verified using Google's Certificate Authority, ensuring that the instance's firmware is unmodified and establishing the root of trust for Secure Boot.\n\nNOTE: You can only enable Shielded VM options on instances that have Shielded VM support. This policy reports VM instances that have Shielded VM support and are disabled with the Shielded VM features.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-TRF-INST-014
#

default compute_instance_external_ip = null

gc_issue["compute_instance_external_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_instance"
    network_interface := resource.properties.network_interface[_]
    has_property(network_interface, "access_config")
    not startswith(lower(resource.properties.name), "gke-")
    not contains(lower(resource.properties.name), "default-pool")
}

compute_instance_external_ip {
    lower(input.resources[i].type) == "google_compute_instance"
    not gc_issue["compute_instance_external_ip"]
}

compute_instance_external_ip = false {
    gc_issue["compute_instance_external_ip"]
}

compute_instance_external_ip_err = "Ensure GCP VM instance not have the external IP address" {
    gc_issue["compute_instance_external_ip"]
}

compute_instance_external_ip_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP VM instance not have the external IP address",
    "Policy Description": "This policy identifies the VM instances with the external IP address associated. To reduce your attack surface, VM instances should not have public/external IP addresses. Instead, instances should be configured behind load balancers, to minimize the instance's exposure to the internet.\n\nNOTE: This policy will not report instances created by GKE because some of them have external IP addresses and cannot be changed by editing the instance settings. Instances created by GKE should be excluded. These instances have names that start with 'gke-' and contains 'default-pool'.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-TRF-INST-015
#

default compute_ip_forwarding_enable = null

gc_issue["compute_ip_forwarding_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_instance"
    resource.properties.can_ip_forward == true
    not startswith(lower(resource.properties.name), "gke-")
}

compute_ip_forwarding_enable {
    lower(input.resources[i].type) == "google_compute_instance"
    not gc_issue["compute_ip_forwarding_enable"]
}

compute_ip_forwarding_enable = false {
    gc_issue["compute_ip_forwarding_enable"]
}

compute_ip_forwarding_enable_err = "Ensure GCP VM instances have IP Forwarding enabled." {
    gc_issue["compute_ip_forwarding_enable"]
}

compute_ip_forwarding_enable_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP VM instances have IP Forwarding enabled.",
    "Policy Description": "This policy checks VM instances that have IP Forwarding enabled. IP Forwarding could open unintended and undesirable communication paths and allows VM instances to send and receive packets with the non-matching destination or source IPs. To enable the source and destination IP match check, disable IP Forwarding.",
    "Resource Type": "google_compute_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}