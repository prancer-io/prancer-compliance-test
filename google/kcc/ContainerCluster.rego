package rule

# https://cloud.google.com/security-command-center/docs/concepts-vulnerabilities-findings#container-findings

#
# CLUSTER_LOGGING_DISABLED
#

default cluster_logging_disabled = null

gc_issue["cluster_logging_disabled"] {
    lower(input.kind) == "containercluster"
    not input.spec.loggingService
}

cluster_logging_disabled {
    lower(input.kind) == "containercluster"
    not gc_issue["cluster_logging_disabled"]
}

cluster_logging_disabled = false {
    gc_issue["cluster_logging_disabled"]
}

cluster_logging_disabled_err = "Logging isn't enabled for a GKE cluster." {
    gc_issue["cluster_logging_disabled"]
}

#
# CLUSTER_MONITORING_DISABLED
#

default cluster_monitoring_disabled = null

gc_issue["cluster_monitoring_disabled"] {
    lower(input.kind) == "containercluster"
    not input.spec.monitoringService
}

cluster_monitoring_disabled {
    lower(input.kind) == "containercluster"
    not gc_issue["cluster_monitoring_disabled"]
}

cluster_monitoring_disabled = false {
    gc_issue["cluster_monitoring_disabled"]
}

cluster_monitoring_disabled_err = "Monitoring is disabled on GKE clusters." {
    gc_issue["cluster_monitoring_disabled"]
}

#
# COS_NOT_USED
#

default cos_not_used = null

gc_issue["cos_not_used"] {
    lower(input.kind) == "containercluster"
    input.spec.nodeConfig.imageType
    lower(input.spec.nodeConfig.imageType) != "cos"
}

cos_not_used {
    lower(input.kind) == "containercluster"
    not gc_issue["cos_not_used"]
}

cos_not_used = false {
    gc_issue["cos_not_used"]
}

cos_not_used_err = "Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely." {
    gc_issue["cos_not_used"]
}

#
# LEGACY_AUTHORIZATION_ENABLED
#

default legacy_authorization_enabled = null

gc_issue["legacy_authorization_enabled"] {
    lower(input.kind) == "containercluster"
    input.spec.enableLegacyAbac
}

legacy_authorization_enabled {
    lower(input.kind) == "containercluster"
    not gc_issue["legacy_authorization_enabled"]
}

legacy_authorization_enabled = false {
    gc_issue["legacy_authorization_enabled"]
}

legacy_authorization_enabled_err = "Legacy Authorization is enabled on GKE clusters." {
    gc_issue["legacy_authorization_enabled"]
}

#
# MASTER_AUTHORIZED_NETWORKS_DISABLED
#

default master_authorized_networks_disabled = null

gc_issue["master_authorized_networks_disabled"] {
    lower(input.kind) == "containercluster"
    not input.spec.masterAuthorizedNetworksConfig
}

master_authorized_networks_disabled {
    lower(input.kind) == "containercluster"
    not gc_issue["master_authorized_networks_disabled"]
}

master_authorized_networks_disabled = false {
    gc_issue["master_authorized_networks_disabled"]
}

master_authorized_networks_disabled_err = "Master Authorized Networks is not enabled on GKE clusters." {
    gc_issue["master_authorized_networks_disabled"]
}

#
# NETWORK_POLICY_DISABLED
#

default network_policy_disabled = null

gc_issue["network_policy_disabled"] {
    lower(input.kind) == "containercluster"
    input.spec.networkPolicy.enabled == false
}

network_policy_disabled {
    lower(input.kind) == "containercluster"
    not gc_issue["network_policy_disabled"]
}

network_policy_disabled = false {
    gc_issue["network_policy_disabled"]
}

network_policy_disabled_err = "Network policy is disabled on GKE clusters." {
    gc_issue["network_policy_disabled"]
}

#
# POD_SECURITY_POLICY_DISABLED
#

default pod_security_policy_disabled = null

gc_issue["pod_security_policy_disabled"] {
    lower(input.kind) == "containercluster"
    input.spec.podSecurityPolicyConfig.enabled == false
}

pod_security_policy_disabled {
    lower(input.kind) == "containercluster"
    not gc_issue["pod_security_policy_disabled"]
}

pod_security_policy_disabled = false {
    gc_issue["pod_security_policy_disabled"]
}

pod_security_policy_disabled_err = "PodSecurityPolicy is disabled on a GKE cluster." {
    gc_issue["pod_security_policy_disabled"]
}

#
# PRIVATE_CLUSTER_DISABLED
#

default private_cluster_disabled = null

gc_issue["private_cluster_disabled"] {
    lower(input.kind) == "containercluster"
    input.spec.privateClusterConfig.enablePrivateNodes == false
}

private_cluster_disabled {
    lower(input.kind) == "containercluster"
    not gc_issue["private_cluster_disabled"]
}

private_cluster_disabled = false {
    gc_issue["private_cluster_disabled"]
}

private_cluster_disabled_err = "A GKE cluster has a Private cluster disabled." {
    gc_issue["private_cluster_disabled"]
}

#
# WEB_UI_ENABLED
#

default web_ui_enabled = null

gc_issue["web_ui_enabled"] {
    lower(input.kind) == "containercluster"
    input.spec.addonsConfig.kubernetesDashboard.disabled == false
}

web_ui_enabled {
    lower(input.kind) == "containercluster"
    not gc_issue["web_ui_enabled"]
}

web_ui_enabled = false {
    gc_issue["web_ui_enabled"]
}

web_ui_enabled_err = "The GKE web UI (dashboard) is enabled." {
    gc_issue["web_ui_enabled"]
}

#
# WORKLOAD_IDENTITY_DISABLED
#

default workload_identity_disabled = null

gc_issue["workload_identity_disabled"] {
    lower(input.kind) == "containercluster"
    not input.spec.workloadIdentityConfig
}

workload_identity_disabled {
    lower(input.kind) == "containercluster"
    not gc_issue["workload_identity_disabled"]
}

workload_identity_disabled = false {
    gc_issue["workload_identity_disabled"]
}

workload_identity_disabled_err = "Workload Identity is disabled on a GKE cluster." {
    gc_issue["workload_identity_disabled"]
}
