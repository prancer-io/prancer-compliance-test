package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters

#
# PR-GCP-TRF-CLT-001
#

default k8s_svc_account = null

gc_issue["k8s_svc_account"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    contains(node_config.service_account, "default")
}

gc_issue["k8s_svc_account"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    node_config.service_account == null
}

k8s_svc_account {
    lower(input.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account_err = "Ensure Kubernetes Engine Cluster Nodes have default Service account for Project access in Google Cloud Provider." {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure Kubernetes Engine Cluster Nodes have default Service account for Project access in Google Cloud Provider.",
    "Policy Description": "This policy identifies Kubernetes Engine Cluster Nodes which have default Service account for Project access. By default, Kubernetes Engine nodes are given the Compute Engine default service account. This account has broad access and more permissions than are required to run your Kubernetes Engine cluster. You should create and use a least privileged service account to run your Kubernetes Engine cluster instead of using the Compute Engine default service account. If you are not creating a separate service account for your nodes, you should limit the scopes of the node service account to reduce the possibility of a privilege escalation in an attack.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-002
#

default k8s_basicauth = null

gc_attribute_absence["k8s_basicauth"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.master_auth
}

gc_attribute_absence["k8s_basicauth"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.master_auth) == 0
}

gc_issue["k8s_basicauth"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    master_auth := resource.properties.master_auth[_]
    count(master_auth.username) > 0
}

gc_issue["k8s_basicauth"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    master_auth := resource.properties.master_auth[_]
    count(master_auth.password) > 0
}

k8s_basicauth {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_basicauth"]
    not gc_attribute_absence["k8s_basicauth"]
}

k8s_basicauth = false {
    gc_issue["k8s_basicauth"]
} else = false {
    gc_attribute_absence["k8s_basicauth"]
}

k8s_basicauth_err = "Ensure GCP Kubernetes Engine Clusters Basic Authentication is not set to Disabled" {
    gc_issue["k8s_basicauth"]
} else = "GCP Kubernetes Engine Clusters attribute master_auth missing in the resource" {
    gc_attribute_absence["k8s_basicauth"]
}

k8s_basicauth_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters Basic Authentication is not set to Disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Basic authentication. Basic authentication allows a user to authenticate to the cluster with a username and password. Disabling Basic authentication will prevent attacks like brute force. Authenticate using client certificate or IAM.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-003
#

default k8s_client_cert = null

gc_attribute_absence["k8s_client_cert"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.master_auth
}

gc_attribute_absence["k8s_client_cert"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.master_auth) == 0
}

gc_attribute_absence["k8s_client_cert"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    master_auth := resource.properties.master_auth[_]
    not master_auth.client_certificate_config
}

gc_attribute_absence["k8s_client_cert"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    master_auth := resource.properties.master_auth[_]
    count(master_auth.client_certificate_config) == 0
}

gc_issue["k8s_client_cert"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    master_auth := resource.properties.master_auth[_]
    client_certificate_config := master_auth.client_certificate_config[_]
    not client_certificate_config.issue_client_certificate
}

k8s_client_cert {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_client_cert"]
    not gc_attribute_absence["k8s_client_cert"]
}

k8s_client_cert = false {
    gc_issue["k8s_client_cert"]
} else = false {
    gc_attribute_absence["k8s_client_cert"]
}

k8s_client_cert_err = "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled" {
    gc_issue["k8s_client_cert"]
} else = "GCP Kubernetes Engine Clusters attribute issue_client_certificate missing in the resource" {
    gc_attribute_absence["k8s_client_cert"]
}

k8s_client_cert_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Client Certificate. A client certificate is a base64-encoded public certificate used by clients to authenticate to the cluster endpoint. Enabling Client Certificate will provide more security to authenticate users to the cluster.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-004
#

default k8s_alias_ip = null

gc_issue["k8s_alias_ip"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count([c | resource.properties.ip_allocation_policy[_] ; c=1]) == 0
}

gc_issue["k8s_alias_ip"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.ip_allocation_policy[_]) == 0
}

k8s_alias_ip {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_alias_ip"]
}

k8s_alias_ip = false {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_err = "Ensure GCP Kubernetes Engine Clusters not have Alias IP enabled" {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have Alias IP enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Alias IP. Alias IP allows the networking layer to perform anti-spoofing checks to ensure that egress traffic is not sent with arbitrary source IPs. By enabling Alias IPs, Kubernetes Engine clusters can allocate IP addresses from a CIDR block known to Google Cloud Platform. This makes your cluster more scalable and allows your cluster to better interact with other GCP products and entities.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-005
#

default k8s_alpha = null

gc_issue["k8s_alpha"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    resource.properties.enable_kubernetes_alpha
}

k8s_alpha {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_alpha"]
}

k8s_alpha = false {
    gc_issue["k8s_alpha"]
}

k8s_alpha_err = "Ensure GCP Kubernetes Engine Clusters not have Alpha cluster feature disabled" {
    gc_issue["k8s_alpha"]
}

k8s_alpha_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have Alpha cluster feature disabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled alpha cluster. It is recommended to not use alpha clusters or alpha features for production workloads. Alpha clusters expire after 30 days and do not receive security updates. This cluster will not be covered by the Kubernetes Engine SLA.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-006
#

default k8s_http_lbs = null

gc_attribute_absence["k8s_http_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.addons_config
}

gc_attribute_absence["k8s_http_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.addons_config) == 0
}

gc_issue["k8s_http_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    addons_config := resource.properties.addons_config[_]
    addons_config.http_load_balancing[_].disabled
}

k8s_http_lbs {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_http_lbs"]
    not gc_attribute_absence["k8s_http_lbs"]
}

k8s_http_lbs = false {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_err = "Ensure GCP Kubernetes Engine Clusters not have HTTP load balancing enabled" {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have HTTP load balancing enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have disabled HTTP load balancing. HTTP/HTTPS load balancing provides global load balancing for HTTP/HTTPS requests destined for your instances. Enabling HTTP/HTTPS load balancers will let the Kubernetes Engine to terminate unauthorized HTTP/HTTPS requests and make better context-aware load balancing decisions.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-007
#

default k8s_legacy_abac = null

gc_issue["k8s_legacy_abac"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    resource.properties.enable_legacy_abac
}

k8s_legacy_abac {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac = false {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_err = "Ensure GCP Kubernetes Engine Clusters not have Legacy Authorization disabled" {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have Legacy Authorization disabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled legacy authorizer. The legacy authorizer in Kubernetes Engine grants broad and statically defined permissions to all cluster users. After legacy authorizer setting is disabled, RBAC can limit permissions for authorized users based on need.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-008
#

default k8s_master_auth_net = null

gc_issue["k8s_master_auth_net"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.master_authorized_networks_config
}

gc_issue["k8s_master_auth_net"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    is_null(resource.properties.master_authorized_networks_config)
}

gc_issue["k8s_master_auth_net"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.master_authorized_networks_config) == 0
}

k8s_master_auth_net {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net = false {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_err = "Ensure GCP Kubernetes Engine Clusters not have Master authorized networks enabled" {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have Master authorized networks enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Master authorized networks. Enabling Master authorized networks will let the Kubernetes Engine block untrusted non-GCP source IPs from accessing the Kubernetes master through HTTPS.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-009
#

default k8s_net_policy = null

gc_attribute_absence["k8s_net_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.network_policy_config
}

gc_attribute_absence["k8s_net_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.network_policy_config) == 0
}

gc_issue["k8s_net_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    network_policy := resource.properties.network_policy_config[_]
    not network_policy.enabled
}

k8s_net_policy {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_net_policy"]
    not gc_attribute_absence["k8s_net_policy"]
}

k8s_net_policy = false {
    gc_issue["k8s_net_policy"]
} else = false {
    gc_attribute_absence["k8s_net_policy"]
}

k8s_net_policy_err = "Ensure GCP Kubernetes Engine Clusters not have Network policy enabled" {
    gc_issue["k8s_net_policy"]
} else = "GCP Kubernetes Engine Clusters attribute network_policy missing in the resource" {
    gc_attribute_absence["k8s_net_policy"]
}

k8s_net_policy_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have Network policy enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Network policy. A network policy defines how groups of pods are allowed to communicate with each other and other network endpoints. By enabling network policy in a namespace for a pod, it will reject any connections that are not allowed by the network policy.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-010
#

default k8s_logging = null

gc_attribute_absence["k8s_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.logging_service
}

gc_issue["k8s_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    lower(resource.properties.logging_service) == "none"
}

k8s_logging {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_logging"]
    not gc_attribute_absence["k8s_logging"]
}

k8s_logging = false {
    gc_issue["k8s_logging"]
}

k8s_logging = false {
    gc_attribute_absence["k8s_logging"]
}

k8s_logging_err = "Ensure GCP Kubernetes Engine Clusters not have Stackdriver Logging enabled" {
    gc_issue["k8s_logging"]
}

k8s_logging_miss_err = "Kubernetes Engine Cluster attribute logging_service config missing in the resource" {
    gc_attribute_absence["k8s_logging"]
}

k8s_logging_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have Stackdriver Logging enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver Logging. Enabling Stackdriver Logging will let the Kubernetes Engine to collect, process, and store your container and system logs in a dedicated persistent data store.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-011
#

default k8s_monitor = null

gc_attribute_absence["k8s_monitor"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.monitoring_service
}

gc_issue["k8s_monitor"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    lower(resource.properties.monitoring_service) == "none"
}

k8s_monitor {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_monitor"]
    not gc_attribute_absence["k8s_monitor"]
}

k8s_monitor = false {
    gc_issue["k8s_monitor"]
}

k8s_monitor = false {
    gc_attribute_absence["k8s_monitor"]
}

k8s_monitor_err = "GCP Kubernetes Engine Clusters have Stackdriver Monitoring disabled" {
    gc_issue["k8s_monitor"]
}

k8s_monitor_miss_err = "Kubernetes Engine Cluster attribute monitoring_service config missing in the resource" {
    gc_attribute_absence["k8s_monitor"]
}

k8s_monitor_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have Stackdriver Monitoring disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver monitoring. Enabling Stackdriver monitoring will let the Kubernetes Engine to monitor signals and build operations in the clusters.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-012
#

default k8s_binary_auth = null

gc_issue["k8s_binary_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.enable_binary_authorization
}

k8s_binary_auth {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_binary_auth"]
}

k8s_binary_auth = false {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_err = "Ensure GCP Kubernetes Engine Clusters not have binary authorization enabled" {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have binary authorization enabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have disabled binary authorization. Binary authorization is a security control that ensures only trusted container images are deployed on GKE clusters. As a best practice, verify images prior to deployment to reduce the risk of running unintended or malicious code in your environment.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-013
#

default k8s_legacy_endpoint = null

gc_attribute_absence["k8s_legacy_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not resource.properties.node_config
}

gc_attribute_absence["k8s_legacy_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    count(resource.properties.node_config) == 0
}

gc_attribute_absence["k8s_legacy_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    not node_config.metadata
}

gc_issue["k8s_legacy_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    node_config.metadata["disable-legacy-endpoints"] == "false"
}

gc_issue["k8s_legacy_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    node_config.metadata["disable-legacy-endpoints"] == false
}

k8s_legacy_endpoint {
    lower(input.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_legacy_endpoint"]
    not gc_attribute_absence["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint = false {
    gc_issue["k8s_legacy_endpoint"]
} else = false {
    gc_attribute_absence["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_err = "Ensure GCP Kubernetes Engine Clusters not have legacy compute engine metadata endpoints disabled" {
    gc_issue["k8s_legacy_endpoint"]
} else = "GCP Kubernetes Engine Clusters attribute metadata of node_config is missing in the resource" {
    gc_attribute_absence["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have legacy compute engine metadata endpoints disabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have legacy compute engine metadata endpoints enabled. Because GKE uses instance metadata to configure node VMs, some of this metadata is potentially sensitive and should be protected from workloads running on the cluster. Legacy metadata APIs expose the Compute Engine's instance metadata of server endpoints. As a best practice, disable legacy API and use v1 APIs to restrict a potential attacker from retrieving instance metadata.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-014
#

default k8s_pod_security = null

gc_attribute_absence["k8s_pod_security"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.pod_security_policy_config
}

gc_attribute_absence["k8s_pod_security"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.pod_security_policy_config) == 0
}

gc_issue["k8s_pod_security"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    pod_security_policy_config := resource.properties.pod_security_policy_config[_]
    not pod_security_policy_config.enabled
}

k8s_pod_security {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_pod_security"]
    not gc_attribute_absence["k8s_pod_security"]
}

k8s_pod_security = false {
    gc_issue["k8s_pod_security"]
} else = false {
    gc_attribute_absence["k8s_pod_security"]
}

k8s_pod_security_err = "Ensure GCP Kubernetes Engine Clusters not have pod security policy enabled" {
    gc_issue["k8s_pod_security"]
} else = "GCP Kubernetes Engine Clusters attribute pod_security_policy_config missing in the resource" {
    gc_attribute_absence["k8s_pod_security"]
}

k8s_pod_security_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters not have pod security policy enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have pod security policy disabled. The Pod Security Policy defines a set of conditions that pods must meet to be accepted by the cluster; when a request to create or update a pod does not meet the conditions in the pod security policy, that request is rejected and an error is returned.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-015
#

default k8s_egress_metering = null

gc_attribute_absence["k8s_egress_metering"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.resource_usage_export_config
}

gc_attribute_absence["k8s_egress_metering"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.resource_usage_export_config) == 0
}

gc_issue["k8s_egress_metering"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    resource_usage_export_config := resource.properties.resource_usage_export_config[_]
    not resource_usage_export_config.enable_network_egress_metering
}

k8s_egress_metering {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_egress_metering"]
    not gc_attribute_absence["k8s_egress_metering"]
}

k8s_egress_metering = false {
    gc_issue["k8s_egress_metering"]
} else = false {
    gc_attribute_absence["k8s_egress_metering"]
}

k8s_egress_metering_err = "Ensure GCP Kubernetes Engine Clusters  configured with network traffic ingress metering" {
    gc_issue["k8s_egress_metering"]
} else = "GCP Kubernetes Engine Clusters attribut enable_network_egress_metering is missing in the resource." {
    gc_attribute_absence["k8s_egress_metering"]
}

k8s_egress_metering_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters  configured with network traffic ingress metering",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with network traffic egress metering. When network traffic egress metering enabled, deployed DaemonSet pod meters network egress traffic by collecting data from the conntrack table, and exports the metered metrics to the specified destination. It is recommended to use, network egress metering so that you will be having data and track over monitored network traffic.<br><br>NOTE: Measuring network egress requires a network metering agent (NMA) running on each node. The NMA runs as a privileged pod, consumes some resources on the node (CPU, memory, and disk space), and enables the nf_conntrack_acct sysctl flag on the kernel (for connection tracking flow accounting). If you are comfortable with these caveats, you can enable network egress tracking for use with GKE usage metering.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-016
#

default k8s_private = null

gc_issue["k8s_private"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.private_cluster_config
}

gc_issue["k8s_private"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    is_null(resource.properties.private_cluster_config)
}

gc_issue["k8s_private"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.private_cluster_config) == 0
}

k8s_private {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_private"]
}

k8s_private = false {
    gc_issue["k8s_private"]
}

k8s_private_err = "GCP Kubernetes Engine Clusters not configured with private cluster" {
    gc_issue["k8s_private"]
}

k8s_private_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-016",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private cluster",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with the Private cluster. Private cluster makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}


#
# PR-GCP-TRF-CLT-017
#

default k8s_private_node = null

gc_attribute_absence["k8s_private_node"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.private_cluster_config
}

gc_issue["k8s_private"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    is_null(resource.properties.private_cluster_config)
}

gc_attribute_absence["k8s_private_node"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.private_cluster_config) == 0
}

gc_issue["k8s_private_node"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    private_cluster_config := resource.properties.private_cluster_config[_]
    private_cluster_config.enable_private_nodes
}

k8s_private_node {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_private_node"]
    not gc_attribute_absence["k8s_private_node"]
}

k8s_private_node = false {
    gc_issue["k8s_private_node"]
} else = false {
    gc_attribute_absence["k8s_private_node"]
}

k8s_private_node_err = "Ensure GCP Kubernetes Engine Clusters configured with private nodes feature to false" {
    gc_issue["k8s_private_node"]
} else = "GCP Kubernetes Engine Clusters attribute enable_private_nodes missing in the resource." {
    gc_attribute_absence["k8s_private_node"]
}

k8s_private_node_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-017",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters configured with private nodes feature to false",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) Clusters which are not configured with the private nodes feature. Private nodes feature makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-018
#

default k8s_node_image = null

gc_attribute_absence["k8s_node_image"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not resource.properties.node_config
}

gc_attribute_absence["k8s_node_image"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    count(resource.properties.node_config) == 0
}

gc_attribute_absence["k8s_node_image"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    not node_config.image_type
}

gc_issue["k8s_node_image"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    not startswith(lower(node_config.image_type), "cos")
}

gc_issue["k8s_node_image"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    not startswith(lower(node_config.image_type), "cos")
}

k8s_node_image {
    lower(input.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_node_image"]
    not gc_attribute_absence["k8s_node_image"]
}

k8s_node_image = false {
    gc_issue["k8s_node_image"]
} else = false {
    gc_attribute_absence["k8s_node_image"]
}

k8s_node_image_err = "Ensure Kubernetes Engine Clusters not using Container-Optimized OS for Node image in Google Cloud Provider" {
    gc_issue["k8s_node_image"]
} else = "Kubernetes Engine Cluster attribute image_type config missing in the resource" {
    gc_attribute_absence["k8s_node_image"]
}

k8s_node_image_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-018",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure Kubernetes Engine Clusters not using Container-Optimized OS for Node image in Google Cloud Provider",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which do not have a container-optimized operating system for node image. Container-Optimized OS is an operating system image for your Compute Engine VMs that is optimized for running Docker containers. By using Container-Optimized OS for node image, you can bring up your Docker containers on Google Cloud Platform quickly, efficiently, and securely. The Container-Optimized OS node image is based on a recent version of the Linux kernel and is optimized to enhance node security. It is also regularly updated with features, security fixes, and patches. The Container-Optimized OS image provides better support, security, and stability than other images.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-019
#

default k8s_network = null


gc_issue["k8s_network"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.network
}

gc_issue["k8s_network"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    is_string(resource.properties.network)
    lower(resource.properties.network) == "default"
}

gc_issue["k8s_network"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    is_null(resource.properties.network)
}

k8s_network {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_network"]
}

k8s_network = false {
    gc_issue["k8s_network"]
}

k8s_network_err = "Ensure Kubernetes Engine Clusters using the default network in Google Cloud Provider" {
    gc_issue["k8s_network"]
}

k8s_network_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-019",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure Kubernetes Engine Clusters using the default network in Google Cloud Provider",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that are configured to use the default network. Because GKE uses this network when creating routes and firewalls for the cluster, as a best practice define a network configuration that meets your security and networking requirements for ingress and egress traffic, instead of using the default network.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-021
#

default k8s_labels = null

gc_issue["k8s_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.resource_labels
}

gc_issue["k8s_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.resource_labels) == 0
}

k8s_labels {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_labels"]
}

k8s_labels = false {
    gc_issue["k8s_labels"]
}

k8s_labels_err = "GCP Kubernetes Engine Clusters not having any label information" {
    gc_issue["k8s_labels"]
}

k8s_labels_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-021",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters not having any label information",
    "Policy Description": "This policy identifies all Kubernetes Engine Clusters which do not have labels. Having a cluster label helps you identify and categorize Kubernetes clusters.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-022
#

default k8s_db_encrypt = null

gc_attribute_absence["k8s_db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.database_encryption
}

gc_issue["k8s_db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    lower(resource.properties.database_encryption[_].state) != "encrypted"
}

gc_issue["k8s_db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.database_encryption[_].key_name) == 0
}

k8s_db_encrypt {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_db_encrypt"]
    not gc_attribute_absence["k8s_db_encrypt"]
}

k8s_db_encrypt = false {
    gc_issue["k8s_db_encrypt"]
}

k8s_db_encrypt = false {
    gc_attribute_absence["k8s_db_encrypt"]
}

k8s_db_encrypt_err = "GCP Kubernetes cluster Application-layer Secrets decrypted" {
    gc_issue["k8s_db_encrypt"]
}

k8s_db_encrypt_miss_err = "Kubernetes Engine Cluster attribute database_encryption config missing in the resource" {
    gc_attribute_absence["k8s_db_encrypt"]
}

k8s_db_encrypt_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-022",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes cluster Application-layer Secrets decrypted",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etcd.<br><br>This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-023
#

default k8s_intra_node = null

gc_issue["k8s_intra_node"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.enable_intranode_visibility
}

k8s_intra_node {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_intra_node"]
}

k8s_intra_node = false {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_err = "GCP Kubernetes cluster intra-node visibility is not enabled" {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-023",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes cluster intra-node visibility is not enabled",
    "Policy Description": "With Intranode Visibility, all network traffic in your cluster is seen by the Google Cloud Platform network. This means you can see flow logs for all traffic between Pods, including traffic between Pods on the same node. And you can create firewall rules that apply to all traffic between Pods.<br><br>This policy checks your cluster's intra-node visibility feature and generates an alert if it's disabled.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-024
#

default k8s_istio = null

gc_attribute_absence["k8s_istio"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.addons_config
}

gc_attribute_absence["k8s_istio"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.addons_config) == 0
}

gc_attribute_absence["k8s_istio"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    addons_config := resource.properties.addons_config[_]
    not addons_config.istio_config
}

gc_attribute_absence["k8s_istio"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    addons_config := resource.properties.addons_config[_]
    count(addons_config.istio_config) == 0
}

gc_issue["k8s_istio"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    addons_config := resource.properties.addons_config[_]
    istio_config := addons_config.istio_config[_]
    istio_config.disabled == false
}

k8s_istio {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_istio"]
    not gc_attribute_absence["k8s_istio"]
}

k8s_istio = false {
    gc_issue["k8s_istio"]
} else = false {
    gc_attribute_absence["k8s_istio"]
}

k8s_istio_err = "GCP Kubernetes cluster istio_config not enabled" {
    gc_issue["k8s_istio"]
} else = "GCP Kubernetes cluster attribute istio_config missing in the resource" {
    gc_attribute_absence["k8s_istio"]
}

k8s_istio_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-024",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes cluster istioConfig not enabled",
    "Policy Description": "Istio is an open service mesh that provides a uniform way to connect, manage, and secure microservices. It supports managing traffic flows between services, enforcing access policies, and aggregating telemetry data, all without requiring changes to the microservice code.<br><br>This policy checks your cluster for the Istio add-on feature and alerts if it is not enabled.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-TRF-CLT-025
#

default k8s_zones = null

gc_issue["k8s_zones"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    resource.properties.location
    count(resource.properties.node_locations) < 3
}

gc_issue["k8s_zones"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    resource.properties.location
    count([c | resource.properties.node_locations[_]; c=1]) == 0
}

k8s_zones {
    lower(input.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_zones"]
}

k8s_zones = false {
    gc_issue["k8s_zones"]
}

k8s_zones_err = "Kubernetes cluster not in redundant zones for Google Cloud Provider" {
    gc_issue["k8s_zones"]
}

k8s_zones_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-025",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Kubernetes cluster not in redundant zones for Google Cloud Provider",
    "Policy Description": "Putting resources in different zones in a region provides isolation from many types of infrastructure, hardware, and software failures.<br><br>This policy alerts if your cluster is not located in at least 3 zones.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}


#
# PR-GCP-TRF-CLT-027
#

default k8s_channel = null

gc_issue["k8s_channel"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.release_channel.channel
}

k8s_channel {
    lower(input.resources[i].type) == "google_container_cluster"
    not gc_issue["k8s_channel"]
}

k8s_channel = false {
    gc_issue["k8s_channel"]
}

k8s_channel_err = "Ensure GCP Kubernetes Engine cluster using Release Channel for version management" {
    gc_issue["k8s_channel"]
}

k8s_channel_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-027",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine cluster using Release Channel for version management",
    "Policy Description": "This policy identifies GCP Kubernetes Engine clusters that are not using Release Channel for version management. Subscribing to a specific release channel reduces version management complexity. \n\nThe Regular release channel upgrades every few weeks and is for production users who need features not yet offered in the Stable channel. These versions have passed internal validation, but don't have enough historical data to guarantee their stability. Known issues generally have known workarounds.\n\nThe Stable release channel upgrades every few months and is for production users who need stability above all else, and for whom frequent upgrades are too risky. These versions have passed internal validation and have been shown to be stable and reliable in production, based on the observed performance of those clusters.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/Shared.Types/ReleaseChannel"
}


#
# PR-GCP-TRF-CLT-028
#

default k8s_workload = null
gc_issue["k8s_workload"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_cluster"
    not startswith(lower(resource.properties.resource_labels["goog-composer-version"]), "composer-1")
    not resource.properties.workload_identity_config
    gc_node_pool_issue["k8s_workload"]
}


gc_node_pool_issue["k8s_workload"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    lower(node_config.workload_metadata_config[_].mode) != "gke_metadata"
}

k8s_workload {
    lower(input.resources[i].type) == "google_container_cluster"
    not gc_issue["k8s_workload"]
}

k8s_workload = false {
    gc_issue["k8s_workload"]
}

k8s_workload_err = "Ensure GCP Kubernetes Engine cluster workload identity is enabled" {
    gc_issue["k8s_workload"]
}

k8s_workload_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-028",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine cluster workload identity is enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine clusters for which workload identity is disabled. Manual approaches for authenticating Kubernetes workloads violates the principle of least privilege on a multi-tenanted node when one pod needs to have access to a service, but every other pod on the node that uses the service account does not. Enabling Workload Identity manages the distribution and rotation of Service account keys for the workloads to use.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeConfig"
}


#
# PR-GCP-TRF-CLT-029
#

default k8s_shield_node = null

gc_issue["k8s_shield_node"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_cluster"
    has_property(resource.properties, "enable_shielded_nodes")
    resource.properties.enable_shielded_nodes == false
}

k8s_shield_node {
    lower(input.resources[i].type) == "google_container_cluster"
    not gc_issue["k8s_shield_node"]
}

k8s_shield_node = false {
    gc_issue["k8s_shield_node"]
}

k8s_shield_node_err = "Ensure GCP Kubernetes cluster Shielded GKE Nodes feature enabled" {
    gc_issue["k8s_shield_node"]
}

k8s_shield_node_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-029",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes cluster Shielded GKE Nodes feature enabled",
    "Policy Description": "This policy identifies GCP Kubernetes clusters for which the Shielded GKE Nodes feature is not enabled. Shielded GKE nodes protect clusters against boot- or kernel-level malware or rootkits\nwhich persist beyond infected OS. It is recommended to enable Shielded GKE Nodes for all the Kubernetes clusters.\n\nFMI: https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster.ShieldedNodes"
}



#
# PR-GCP-TRF-CLT-030
#

default k8s_node_autorepair = null

gc_issue["k8s_node_autorepair"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_node_pool"
    management := resource.properties.node_config[_].management[_]
    not management.auto_repair
}

k8s_node_autorepair {
    lower(input.resources[i].type) == "google_container_node_pool"
    not gc_issue["k8s_node_autorepair"]
}

k8s_node_autorepair = false {
    gc_issue["k8s_node_autorepair"]
}

k8s_node_autorepair_err = "Ensure GCP Kubernetes cluster node auto-repair configuration enabled" {
    gc_issue["k8s_node_autorepair"]
}

k8s_node_autorepair_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-030",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes cluster node auto-repair configuration enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster nodes with auto-repair configuration disabled. GKE's node auto-repair feature helps you keep the nodes in your cluster in a healthy, running state. When enabled, GKE makes periodic checks on the health state of each node in your cluster. If a node fails consecutive health checks over an extended time period, GKE initiates a repair process for that node.\n\nFMI: https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair",
    "Resource Type": "google_container_node_pool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}


#
# PR-GCP-TRF-CLT-031
#

default k8s_node_autoupgrade = null

gc_issue["k8s_node_autoupgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_node_pool"
    management := resource.properties.node_config[_].management[_]
    not management.auto_upgrade
}

k8s_node_autoupgrade {
    lower(input.resources[i].type) == "google_container_node_pool"
    not gc_issue["k8s_node_autoupgrade"]
}

k8s_node_autoupgrade = false {
    gc_issue["k8s_node_autoupgrade"]
}

k8s_node_autoupgrade_err = "Ensure GCP Kubernetes cluster node auto-upgrade configuration enabled" {
    gc_issue["k8s_node_autoupgrade"]
}

k8s_node_autoupgrade_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-031",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes cluster node auto-upgrade configuration enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster nodes with auto-upgrade configuration disabled. Node auto-upgrades help you keep the nodes in your cluster up to date with the cluster master version when your master is updated on your behalf. When you create a new cluster using Google Cloud Platform Console, node auto-upgrade is enabled by default.\n\nFMI: https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades",
    "Resource Type": "google_container_node_pool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}


#
# PR-GCP-TRF-CLT-032
#

default k8s_secure_boot = null

gc_issue["k8s_secure_boot"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_node_pool"
    node_pool := resource.properties.node_config[_]
    shielded_instance_config := node_pool.shielded_instance_config[_]
    not shielded_instance_config.enable_secure_boot
}

k8s_secure_boot {
    lower(input.resources[i].type) == "google_container_node_pool"
    not gc_issue["k8s_secure_boot"]
}

k8s_secure_boot = false {
    gc_issue["k8s_secure_boot"]
}

k8s_secure_boot_err = "Ensure GCP Kubernetes cluster shielded GKE node with Secure Boot enabled" {
    gc_issue["k8s_secure_boot"]
}

k8s_secure_boot_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-032",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes cluster shielded GKE node with Secure Boot enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster shielded GKE nodes with Secure Boot disabled. An attacker may seek to alter boot components to persist malware or rootkits during system initialization. It is recommended to enable Secure Boot for Shielded GKE Nodes to verify the digital signature of node boot components.",
    "Resource Type": "google_container_node_pool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}


#
# PR-GCP-TRF-CLT-033
#

default k8s_integrity_monitor = null

gc_issue["k8s_integrity_monitor"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_node_pool"
    node_pool := resource.properties.node_config[_]
    shielded_instance_config := node_pool.shielded_instance_config[_]
    not shielded_instance_config.enable_integrity_monitoring
}

k8s_integrity_monitor {
    lower(input.resources[i].type) == "google_container_node_pool"
    not gc_issue["k8s_integrity_monitor"]
}

k8s_integrity_monitor = false {
    gc_issue["k8s_integrity_monitor"]
}

k8s_integrity_monitor_err = "Ensure GCP Kubernetes cluster shielded GKE node with integrity monitoring enabled" {
    gc_issue["k8s_integrity_monitor"]
}

k8s_integrity_monitor_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-033",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes cluster shielded GKE node with integrity monitoring enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster shielded GKE nodes that are not enabled with Integrity Monitoring. Integrity Monitoring provides active alerting for Shielded GKE nodes which allows administrators to respond to integrity failures and prevent compromised nodes from being deployed into the cluster.",
    "Resource Type": "google_container_node_pool",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}


#
# PR-GCP-TRF-CLT-034
#

default secret_encrypted = null

gc_issue["secret_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_cluster"
    decryption := resource.properties.database_encryption[_]
    upper(decryption.state) == "DECRYPTED"
} 

secret_encrypted{
    lower(input.resources[i].type) == "google_container_cluster"
    not gc_issue["secret_encrypted"]
}

secret_encrypted = false{
    gc_issue["secret_encrypted"]
}

secret_encrypted_err = "Ensure GCP Kubernetes cluster Application-layer Secrets are decrypted."{
    gc_issue["secret_encrypted"]
}

secret_encrypted_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-034",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes cluster Application-layer Secrets are decrypted.",
    "Policy Description": "This policy established Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etc. This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}


#
# PR-GCP-TRF-CLT-035
#

default private_endpoint_disabled = null


gc_issue["private_endpoint_disabled"] {
    resource := input.resources[i]
    lower(resource.type) == "google_container_cluster"
    has_property(resource.properties, "private_cluster_config")
	count([c | resource.properties.private_cluster_config[_].enable_private_nodes; c=1]) == 0
}


private_endpoint_disabled {
    not gc_issue["private_endpoint_disabled"]
}

private_endpoint_disabled = false{
    gc_issue["private_endpoint_disabled"]
}

private_endpoint_disabled_err = "Ensure GCP Kubernetes Engine private cluster has private endpoint disabled."{
    gc_issue["private_endpoint_disabled"]
}

private_endpoint_disabled_metadata := {
    "Policy Code": "PR-GCP-TRF-CLT-035",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Kubernetes Engine private cluster has private endpoint disabled.",
    "Policy Description": "This policy finds GCP Kubernetes Engine private clusters with private endpoint disabled. A public endpoint might expose the current cluster and Kubernetes API version and an attacker may be able to determine whether it is vulnerable to an attack. Unless required, disabling the public endpoint will help prevent such threats, and require the attacker to be on the master's VPC network to perform any attack on the Kubernetes API. It is recommended to enable the private endpoint and disable public access on Kubernetes clusters.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}