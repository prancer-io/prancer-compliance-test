package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containernodepool

#
# AUTO_REPAIR_DISABLED
#

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

#
# AUTO_UPGRADE_DISABLED
#

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

#
# COS_NOT_USED
#

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

#
# LEGACY_METADATA_ENABLED
#

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
