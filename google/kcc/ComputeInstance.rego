package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance

#
# COMPUTE_SECURE_BOOT_DISABLED
# PR-GCP-0025-KCC

default compute_secure_boot_disabled = null

gc_issue["compute_secure_boot_disabled"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableSecureBoot
}

gc_issue["compute_secure_boot_disabled"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableIntegrityMonitoring
}

gc_issue["compute_secure_boot_disabled"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableVtpm
}

compute_secure_boot_disabled {
    lower(input.kind) == "computeinstance"
    not gc_issue["compute_secure_boot_disabled"]
}

compute_secure_boot_disabled = false {
    gc_issue["compute_secure_boot_disabled"]
}

compute_secure_boot_disabled_err = "This Shielded VM does not have Secure Boot enabled." {
    gc_issue["compute_secure_boot_disabled"]
}

compute_secure_boot_disabled_metadata := {
    "Policy Code": "COMPUTE_SECURE_BOOT_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Compute Secure Boot Disabled",
    "Policy Description": "This Shielded VM does not have Secure Boot enabled.",
    "Resource Type": "ComputeInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance"
}

#
# COMPUTE_SERIAL_PORTS_ENABLED
# PR-GCP-0026-KCC

default compute_serial_ports_enabled = null

gc_issue["compute_serial_ports_enabled"] {
    lower(input.kind) == "computeinstance"
    items := input.spec.metadata.items[_]
    contains(lower(items.key), "serial-port-enable")
    lower(items.value) == "true"
}

compute_serial_ports_enabled {
    lower(input.kind) == "computeinstance"
    not gc_issue["compute_serial_ports_enabled"]
}

compute_serial_ports_enabled = false {
    gc_issue["compute_serial_ports_enabled"]
}

compute_serial_ports_enabled_err = "Serial ports are enabled for an instance, allowing connections to the instance's serial console." {
    gc_issue["compute_serial_ports_enabled"]
}

compute_serial_ports_enabled_metadata := {
    "Policy Code": "COMPUTE_SERIAL_PORTS_ENABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Compute Serial Ports Enabled",
    "Policy Description": "Serial ports are enabled for an instance, allowing connections to the instance's serial console.",
    "Resource Type": "ComputeInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance"
}

#
# IP_FORWARDING_ENABLED
# PR-GCP-0027-KCC

default ip_forwarding_enabled = null

gc_issue["ip_forwarding_enabled"] {
    lower(input.kind) == "computeinstance"
    input.spec.canIpForward
}

ip_forwarding_enabled {
    lower(input.kind) == "computeinstance"
    not gc_issue["ip_forwarding_enabled"]
}

ip_forwarding_enabled = false {
    gc_issue["ip_forwarding_enabled"]
}

ip_forwarding_enabled_err = "IP forwarding is enabled on instances." {
    gc_issue["ip_forwarding_enabled"]
}

ip_forwarding_enabled_metadata := {
    "Policy Code": "IP_FORWARDING_ENABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "IP Forwarding Enabled",
    "Policy Description": "IP forwarding is enabled on instances.",
    "Resource Type": "ComputeInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance"
}

#
# OS_LOGIN_DISABLED
# PR-GCP-0028-KCC

default os_login_disabled = null

gc_issue["os_login_disabled"] {
    lower(input.kind) == "computeinstance"
    items := input.spec.metadata.items[_]
    contains(lower(items.key), "enable-oslogin")
    lower(items.value) == "true"
}

os_login_disabled {
    lower(input.kind) == "computeinstance"
    not gc_issue["os_login_disabled"]
}

os_login_disabled = false {
    gc_issue["os_login_disabled"]
}

os_login_disabled_err = "OS Login is disabled on this instance." {
    gc_issue["os_login_disabled"]
}

os_login_disabled_metadata := {
    "Policy Code": "OS_LOGIN_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "OS Login Disabled",
    "Policy Description": "OS Login is disabled on this instance.",
    "Resource Type": "ComputeInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance"
}

#
# PUBLIC_IP_ADDRESS
# PR-GCP-0029-KCC

default public_ip_address = null

gc_issue["public_ip_address"] {
    lower(input.kind) == "computeinstance"
    input.spec.networkInterface.accessConfigs
}

public_ip_address {
    lower(input.kind) == "computeinstance"
    not gc_issue["public_ip_address"]
}

public_ip_address = false {
    gc_issue["public_ip_address"]
}

public_ip_address_err = "An instance has a public IP address." {
    gc_issue["public_ip_address"]
}

public_ip_address_metadata := {
    "Policy Code": "PUBLIC_IP_ADDRESS",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Public IP Address",
    "Policy Description": "An instance has a public IP address.",
    "Resource Type": "ComputeInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance"
}

#
# SHIELDED_VM_DISABLED
# PR-GCP-0030-KCC

default shielded_vm_disabled = null

gc_issue["shielded_vm_disabled"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableSecureBoot
}

gc_issue["shielded_vm_disabled"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableIntegrityMonitoring
}

gc_issue["shielded_vm_disabled"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableVtpm
}

shielded_vm_disabled {
    lower(input.kind) == "computeinstance"
    not gc_issue["shielded_vm_disabled"]
}

shielded_vm_disabled = false {
    gc_issue["shielded_vm_disabled"]
}

shielded_vm_disabled_err = "Shielded VM is disabled on this instance." {
    gc_issue["shielded_vm_disabled"]
}

shielded_vm_disabled_metadata := {
    "Policy Code": "SHIELDED_VM_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Shielded VM Disabled",
    "Policy Description": "Shielded VM is disabled on this instance.",
    "Resource Type": "ComputeInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance"
}

#
# ORG_POLICY_CONFIDENTIAL_VM_POLICY
# PR-GCP-0031-KCC

default org_policy_confidential_vm_policy = null

gc_issue["org_policy_confidential_vm_policy"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableSecureBoot
}

gc_issue["org_policy_confidential_vm_policy"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableIntegrityMonitoring
}

gc_issue["org_policy_confidential_vm_policy"] {
    lower(input.kind) == "computeinstance"
    not input.spec.shieldedInstanceConfig.enableVtpm
}

org_policy_confidential_vm_policy {
    lower(input.kind) == "computeinstance"
    not gc_issue["org_policy_confidential_vm_policy"]
}

org_policy_confidential_vm_policy = false {
    gc_issue["org_policy_confidential_vm_policy"]
}

org_policy_confidential_vm_policy_err = "A Compute Engine resource is out of compliance with the constraints/compute." {
    gc_issue["org_policy_confidential_vm_policy"]
}

org_policy_confidential_vm_policy_metadata := {
    "Policy Code": "ORG_POLICY_CONFIDENTIAL_VM_POLICY",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Org Policy Confidential VM Policy",
    "Policy Description": "A Compute Engine resource is out of compliance with the constraints/compute.",
    "Resource Type": "ComputeInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance"
}
