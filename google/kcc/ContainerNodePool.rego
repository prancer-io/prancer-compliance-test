package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containernodepool

#
# AUTO_REPAIR_DISABLED
# PR-GCP-0045-KCC

default auto_repair_disabled = null

gc_issue["auto_repair_disabled"] {
    lower(input.kind) == "containernodepool"
    not input.spec.management.autoRepair
}

auto_repair_disabled {
    lower(input.kind) == "containernodepool"
    not gc_issue["auto_repair_disabled"]
}

auto_repair_disabled = false {
    gc_issue["auto_repair_disabled"]
}

auto_repair_disabled_err = "A GKE cluster's auto repair feature, which keeps nodes in a healthy, running state, is disabled." {
    gc_issue["auto_repair_disabled"]
}

auto_repair_disabled_metadata := {
    "Policy Code": "AUTO_REPAIR_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Auto Repair Disabled",
    "Policy Description": "A GKE cluster's auto repair feature, which keeps nodes in a healthy, running state, is disabled.",
    "Resource Type": "ContainerNodePool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containernodepool"
}

#
# AUTO_UPGRADE_DISABLED
# PR-GCP-0046-KCC

default auto_upgrade_disabled = null

gc_issue["auto_upgrade_disabled"] {
    lower(input.kind) == "containernodepool"
    not input.spec.management.autoUpgrade
}

auto_upgrade_disabled {
    lower(input.kind) == "containernodepool"
    not gc_issue["auto_upgrade_disabled"]
}

auto_upgrade_disabled = false {
    gc_issue["auto_upgrade_disabled"]
}

auto_upgrade_disabled_err = "A GKE cluster's auto upgrade feature, which keeps clusters and node pools on the latest stable version of Kubernetes, is disabled." {
    gc_issue["auto_upgrade_disabled"]
}

auto_upgrade_disabled_metadata := {
    "Policy Code": "AUTO_UPGRADE_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Auto Upgrade Disabled",
    "Policy Description": "A GKE cluster's auto upgrade feature, which keeps clusters and node pools on the latest stable version of Kubernetes, is disabled.",
    "Resource Type": "ContainerNodePool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containernodepool"
}

#
# COS_NOT_USED
# PR-GCP-0047-KCC

default cos_not_used = null

gc_issue["cos_not_used"] {
    lower(input.kind) == "containernodepool"
    not input.spec.nodeConfig.imageType
}

gc_issue["cos_not_used"] {
    lower(input.kind) == "containernodepool"
    lower(input.spec.nodeConfig.imageType) != "cos"
}

cos_not_used {
    lower(input.kind) == "containernodepool"
    not gc_issue["cos_not_used"]
}

cos_not_used = false {
    gc_issue["cos_not_used"]
}

cos_not_used_err = "Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely." {
    gc_issue["cos_not_used"]
}

cos_not_used_metadata := {
    "Policy Code": "COS_NOT_USED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "COS Not Used",
    "Policy Description": "Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.",
    "Resource Type": "ContainerNodePool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containernodepool"
}

#
# LEGACY_METADATA_ENABLED
# PR-GCP-0048-KCC

default legacy_metadata_enabled = null

gc_issue["legacy_metadata_enabled"] {
    lower(input.kind) == "containernodepool"
    input.spec.nodeConfig["metadata.disable-legacy-endpoints"] == "false"
}

legacy_metadata_enabled {
    lower(input.kind) == "containernodepool"
    not gc_issue["legacy_metadata_enabled"]
}

legacy_metadata_enabled = false {
    gc_issue["legacy_metadata_enabled"]
}

legacy_metadata_enabled_err = "Legacy metadata is enabled on GKE clusters." {
    gc_issue["legacy_metadata_enabled"]
}

legacy_metadata_enabled_metadata := {
    "Policy Code": "LEGACY_METADATA_ENABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Legacy Metadata Enabled",
    "Policy Description": "Legacy metadata is enabled on GKE clusters.",
    "Resource Type": "ContainerNodePool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containernodepool"
}
