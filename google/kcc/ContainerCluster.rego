package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster

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

cluster_logging_disabled_metadata := {
    "Policy Code": "CLUSTER_LOGGING_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Cluster Logging Disabled",
    "Policy Description": "Logging isn't enabled for a GKE cluster.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

cluster_monitoring_disabled_metadata := {
    "Policy Code": "CLUSTER_MONITORING_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Cluster Monitoring Disabled",
    "Policy Description": "Monitoring is disabled on GKE clusters.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

cos_not_used_metadata := {
    "Policy Code": "COS_NOT_USED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "COS Not Used",
    "Policy Description": "Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

legacy_authorization_enabled_metadata := {
    "Policy Code": "LEGACY_AUTHORIZATION_ENABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Legacy Authorization Enabled",
    "Policy Description": "Legacy Authorization is enabled on GKE clusters.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

master_authorized_networks_disabled_metadata := {
    "Policy Code": "MASTER_AUTHORIZED_NETWORKS_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Master Authorized Networks Disabled",
    "Policy Description": "Master Authorized Networks is not enabled on GKE clusters.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

network_policy_disabled_metadata := {
    "Policy Code": "NETWORK_POLICY_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Network Policy Disabled",
    "Policy Description": "Network policy is disabled on GKE clusters.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

pod_security_policy_disabled_metadata := {
    "Policy Code": "POD_SECURITY_POLICY_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Pod Security Policy Disabled",
    "Policy Description": "PodSecurityPolicy is disabled on a GKE cluster.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

private_cluster_disabled_metadata := {
    "Policy Code": "PRIVATE_CLUSTER_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Private Cluster Disabled",
    "Policy Description": "A GKE cluster has a Private cluster disabled.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

web_ui_enabled_metadata := {
    "Policy Code": "WEB_UI_ENABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Web UI Enabled",
    "Policy Description": "The GKE web UI (dashboard) is enabled.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
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

workload_identity_disabled_metadata := {
    "Policy Code": "WORKLOAD_IDENTITY_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Workload Identity Disabled",
    "Policy Description": "Workload Identity is disabled on a GKE cluster.",
    "Resource Type": "ContainerCluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/container/containercluster"
}
