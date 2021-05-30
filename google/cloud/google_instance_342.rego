#
# PR-GCP-0072
#

package rule
default rulepass = false

# metadata.items[*].key contains serial-port-enable and metadata.items[*].value contains true'

rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(metadata) == 1
}

# nodePools[*].config.serviceAccount contains default
metadata["input.items"] {
    input.metadata.items[_].key = "serial-port-enable"
    input.metadata.items[_].value = "true"

}

metadata := {
    "Policy Code": "PR-GCP-0072",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP VM instances have serial port access enabled",
    "Policy Description": "This policy identifies VM instances which have serial port access enabled. Interacting with a serial port is often referred to as the serial console. The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. So it is recommended to keep interactive serial console support disabled.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
