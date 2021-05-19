package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computeinstance

#
# COMPUTE_SECURE_BOOT_DISABLED
#

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

#
# COMPUTE_SERIAL_PORTS_ENABLED
#

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

#
# IP_FORWARDING_ENABLED
#

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

#
# OS_LOGIN_DISABLED
#

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

os_login_disabled_err = "Serial ports are enabled for an instance, allowing connections to the instance's serial console." {
    gc_issue["os_login_disabled"]
}

#
# PUBLIC_IP_ADDRESS
#

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

#
# SHIELDED_VM_DISABLED
#

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
