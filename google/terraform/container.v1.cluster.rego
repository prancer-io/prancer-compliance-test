package rule

# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters

#
# PR-GCP-0030-TRF
#

default k8s_svc_account = null

gc_attribute_absence["k8s_svc_account"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not resource.properties.node_config
}

gc_attribute_absence["k8s_svc_account"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    count(resource.properties.node_config) == 0
}

gc_issue["k8s_svc_account"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    not node_config.service_account
}

gc_issue["k8s_svc_account"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    node_config := resource.properties.node_config[_]
    is_null(node_config.service_account)
}

k8s_svc_account {
    lower(input.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_svc_account"]
    not gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_issue["k8s_svc_account"]
} else = false {
    gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account_err = "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access" {
    gc_issue["k8s_svc_account"]
} else = "Kubernetes Engine Cluster attribute nodePools config missing in the resource" {
    gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account_metadata := {
    "Policy Code": "PR-GCP-0030-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access",
    "Policy Description": "This policy identifies Kubernetes Engine Cluster Nodes which have default Service account for Project access. By default, Kubernetes Engine nodes are given the Compute Engine default service account. This account has broad access and more permissions than are required to run your Kubernetes Engine cluster. You should create and use a least privileged service account to run your Kubernetes Engine cluster instead of using the Compute Engine default service account. If you are not creating a separate service account for your nodes, you should limit the scopes of the node service account to reduce the possibility of a privilege escalation in an attack.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0031-TRF
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

k8s_basicauth_err = "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled" {
    gc_issue["k8s_basicauth"]
} else = "GCP Kubernetes Engine Clusters attribute master_auth missing in the resource" {
    gc_attribute_absence["k8s_basicauth"]
}

k8s_basicauth_metadata := {
    "Policy Code": "PR-GCP-0031-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Basic authentication. Basic authentication allows a user to authenticate to the cluster with a username and password. Disabling Basic authentication will prevent attacks like brute force. Authenticate using client certificate or IAM.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0032-TRF
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
    "Policy Code": "PR-GCP-0032-TRF",
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
# PR-GCP-0033-TRF
#

default k8s_alias_ip = null

gc_issue["k8s_alias_ip"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.ip_allocation_policy
}

k8s_alias_ip {
    lower(input.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_alias_ip"]
}

k8s_alias_ip = false {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_err = "GCP Kubernetes Engine Clusters have Alias IP disabled" {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_metadata := {
    "Policy Code": "PR-GCP-0033-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alias IP disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Alias IP. Alias IP allows the networking layer to perform anti-spoofing checks to ensure that egress traffic is not sent with arbitrary source IPs. By enabling Alias IPs, Kubernetes Engine clusters can allocate IP addresses from a CIDR block known to Google Cloud Platform. This makes your cluster more scalable and allows your cluster to better interact with other GCP products and entities.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0034-TRF
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

k8s_alpha_err = "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled" {
    gc_issue["k8s_alpha"]
}

k8s_alpha_metadata := {
    "Policy Code": "PR-GCP-0034-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled alpha cluster. It is recommended to not use alpha clusters or alpha features for production workloads. Alpha clusters expire after 30 days and do not receive security updates. This cluster will not be covered by the Kubernetes Engine SLA.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0035-TRF
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

k8s_http_lbs_err = "GCP Kubernetes Engine Clusters have HTTP load balancing disabled" {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_metadata := {
    "Policy Code": "PR-GCP-0035-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have HTTP load balancing disabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have disabled HTTP load balancing. HTTP/HTTPS load balancing provides global load balancing for HTTP/HTTPS requests destined for your instances. Enabling HTTP/HTTPS load balancers will let the Kubernetes Engine to terminate unauthorized HTTP/HTTPS requests and make better context-aware load balancing decisions.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0036-TRF
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

k8s_legacy_abac_err = "GCP Kubernetes Engine Clusters have Legacy Authorization enabled" {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_metadata := {
    "Policy Code": "PR-GCP-0036-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have Legacy Authorization enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled legacy authorizer. The legacy authorizer in Kubernetes Engine grants broad and statically defined permissions to all cluster users. After legacy authorizer setting is disabled, RBAC can limit permissions for authorized users based on need.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0037-TRF
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

k8s_master_auth_net_err = "GCP Kubernetes Engine Clusters have Master authorized networks disabled" {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_metadata := {
    "Policy Code": "PR-GCP-0037-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have Master authorized networks disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Master authorized networks. Enabling Master authorized networks will let the Kubernetes Engine block untrusted non-GCP source IPs from accessing the Kubernetes master through HTTPS.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0038-TRF
#

default k8s_net_policy = null

gc_attribute_absence["k8s_net_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.network_policy
}

gc_attribute_absence["k8s_net_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.network_policy) == 0
}

gc_issue["k8s_net_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_cluster"
    network_policy := resource.properties.network_policy[_]
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

k8s_net_policy_err = "GCP Kubernetes Engine Clusters have Network policy disabled" {
    gc_issue["k8s_net_policy"]
} else = "GCP Kubernetes Engine Clusters attribute network_policy missing in the resource" {
    gc_attribute_absence["k8s_net_policy"]
}

k8s_net_policy_metadata := {
    "Policy Code": "PR-GCP-0038-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have Network policy disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Network policy. A network policy defines how groups of pods are allowed to communicate with each other and other network endpoints. By enabling network policy in a namespace for a pod, it will reject any connections that are not allowed by the network policy.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0039-TRF
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

k8s_logging_err = "GCP Kubernetes Engine Clusters have Stackdriver Logging disabled" {
    gc_issue["k8s_logging"]
}

k8s_logging_miss_err = "Kubernetes Engine Cluster attribute logging_service config missing in the resource" {
    gc_attribute_absence["k8s_logging"]
}

k8s_logging_metadata := {
    "Policy Code": "PR-GCP-0039-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have Stackdriver Logging disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver Logging. Enabling Stackdriver Logging will let the Kubernetes Engine to collect, process, and store your container and system logs in a dedicated persistent data store.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0040-TRF
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
    "Policy Code": "PR-GCP-0040-TRF",
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
# PR-GCP-0041-TRF
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

k8s_binary_auth_err = "GCP Kubernetes Engine Clusters have binary authorization disabled" {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_metadata := {
    "Policy Code": "PR-GCP-0041-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have binary authorization disabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have disabled binary authorization. Binary authorization is a security control that ensures only trusted container images are deployed on GKE clusters. As a best practice, verify images prior to deployment to reduce the risk of running unintended or malicious code in your environment.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0042-TRF
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

k8s_legacy_endpoint_err = "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled" {
    gc_issue["k8s_legacy_endpoint"]
} else = "GCP Kubernetes Engine Clusters attribute metadata of node_config is missing in the resource" {
    gc_attribute_absence["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_metadata := {
    "Policy Code": "PR-GCP-0042-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have legacy compute engine metadata endpoints enabled. Because GKE uses instance metadata to configure node VMs, some of this metadata is potentially sensitive and should be protected from workloads running on the cluster. Legacy metadata APIs expose the Compute Engine's instance metadata of server endpoints. As a best practice, disable legacy API and use v1 APIs to restrict a potential attacker from retrieving instance metadata.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0043-TRF
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

k8s_pod_security_err = "GCP Kubernetes Engine Clusters have pod security policy disabled" {
    gc_issue["k8s_pod_security"]
} else = "GCP Kubernetes Engine Clusters attribute pod_security_policy_config missing in the resource" {
    gc_attribute_absence["k8s_pod_security"]
}

k8s_pod_security_metadata := {
    "Policy Code": "PR-GCP-0043-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters have pod security policy disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have pod security policy disabled. The Pod Security Policy defines a set of conditions that pods must meet to be accepted by the cluster; when a request to create or update a pod does not meet the conditions in the pod security policy, that request is rejected and an error is returned.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0045-TRF
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

k8s_egress_metering_err = "GCP Kubernetes Engine Clusters not configured with network traffic egress metering" {
    gc_issue["k8s_egress_metering"]
} else = "GCP Kubernetes Engine Clusters attribut enable_network_egress_metering is missing in the resource." {
    gc_attribute_absence["k8s_egress_metering"]
}

k8s_egress_metering_metadata := {
    "Policy Code": "PR-GCP-0045-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with network traffic egress metering",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with network traffic egress metering. When network traffic egress metering enabled, deployed DaemonSet pod meters network egress traffic by collecting data from the conntrack table, and exports the metered metrics to the specified destination. It is recommended to use, network egress metering so that you will be having data and track over monitored network traffic.<br><br>NOTE: Measuring network egress requires a network metering agent (NMA) running on each node. The NMA runs as a privileged pod, consumes some resources on the node (CPU, memory, and disk space), and enables the nf_conntrack_acct sysctl flag on the kernel (for connection tracking flow accounting). If you are comfortable with these caveats, you can enable network egress tracking for use with GKE usage metering.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0046-TRF
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

#
# PR-GCP-0047-TRF
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

k8s_private_node_err = "GCP Kubernetes Engine Clusters not configured with private nodes feature" {
    gc_issue["k8s_private_node"]
} else = "GCP Kubernetes Engine Clusters attribute enable_private_nodes missing in the resource." {
    gc_attribute_absence["k8s_private_node"]
}

k8s_private_node_metadata := {
    "Policy Code": "PR-GCP-0046-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private cluster",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with the Private cluster. Private cluster makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

k8s_private_metadata := {
    "Policy Code": "PR-GCP-0047-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private nodes feature",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) Clusters which are not configured with the private nodes feature. Private nodes feature makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0048-TRF
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
    not startswith(lower(node_config.config.image_type), "cos")
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

k8s_node_image_err = "GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image" {
    gc_issue["k8s_node_image"]
} else = "Kubernetes Engine Cluster attribute image_type config missing in the resource" {
    gc_attribute_absence["k8s_node_image"]
}

k8s_node_image_metadata := {
    "Policy Code": "PR-GCP-0048-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which do not have a container-optimized operating system for node image. Container-Optimized OS is an operating system image for your Compute Engine VMs that is optimized for running Docker containers. By using Container-Optimized OS for node image, you can bring up your Docker containers on Google Cloud Platform quickly, efficiently, and securely. The Container-Optimized OS node image is based on a recent version of the Linux kernel and is optimized to enhance node security. It is also regularly updated with features, security fixes, and patches. The Container-Optimized OS image provides better support, security, and stability than other images.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0049-TRF
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

k8s_network_err = "GCP Kubernetes Engine Clusters using the default network" {
    gc_issue["k8s_network"]
}

k8s_network_metadata := {
    "Policy Code": "PR-GCP-0049-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters using the default network",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that are configured to use the default network. Because GKE uses this network when creating routes and firewalls for the cluster, as a best practice define a network configuration that meets your security and networking requirements for ingress and egress traffic, instead of using the default network.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0051-TRF
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

k8s_labels_err = "GCP Kubernetes Engine Clusters without any label information" {
    gc_issue["k8s_labels"]
}

k8s_labels_metadata := {
    "Policy Code": "PR-GCP-0051-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes Engine Clusters without any label information",
    "Policy Description": "This policy identifies all Kubernetes Engine Clusters which do not have labels. Having a cluster label helps you identify and categorize Kubernetes clusters.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0052-TRF
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

k8s_db_encrypt_err = "GCP Kubernetes cluster Application-layer Secrets not encrypted" {
    gc_issue["k8s_db_encrypt"]
}

k8s_db_encrypt_miss_err = "Kubernetes Engine Cluster attribute database_encryption config missing in the resource" {
    gc_attribute_absence["k8s_db_encrypt"]
}

k8s_db_encrypt_metadata := {
    "Policy Code": "PR-GCP-0052-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes cluster Application-layer Secrets not encrypted",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etcd.<br><br>This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0053-TRF
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

k8s_intra_node_err = "GCP Kubernetes cluster intra-node visibility disabled" {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_metadata := {
    "Policy Code": "PR-GCP-0053-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes cluster intra-node visibility disabled",
    "Policy Description": "With Intranode Visibility, all network traffic in your cluster is seen by the Google Cloud Platform network. This means you can see flow logs for all traffic between Pods, including traffic between Pods on the same node. And you can create firewall rules that apply to all traffic between Pods.<br><br>This policy checks your cluster's intra-node visibility feature and generates an alert if it's disabled.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-0054-TRF
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
    "Policy Code": "PR-GCP-0054-TRF",
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
# PR-GCP-0055-TRF
#

default k8s_zones = null

gc_issue["k8s_zones"] {
    resource := input.resources[_]
    lower(resource.type) == "google_container_node_pool"
    resource.properties.zone
    count(resource.properties.node_locations) < 3
}

k8s_zones {
    lower(input.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_zones"]
}

k8s_zones = false {
    gc_issue["k8s_zones"]
}

k8s_zones_err = "GCP Kubernetes cluster Application-layer Secrets not encrypted" {
    gc_issue["k8s_zones"]
}

k8s_zones_miss_err = "GCP Kubernetes cluster not in redundant zones" {
    gc_attribute_absence["k8s_zones"]
}

k8s_zones_metadata := {
    "Policy Code": "PR-GCP-0055-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Kubernetes cluster not in redundant zones",
    "Policy Description": "Putting resources in different zones in a region provides isolation from many types of infrastructure, hardware, and software failures.<br><br>This policy alerts if your cluster is not located in at least 3 zones.",
    "Resource Type": "google_container_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}