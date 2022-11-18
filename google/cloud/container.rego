package rule

# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

#
# PR-GCP-CLD-CLT-001
#

default k8s_svc_account = null

gc_attribute_absence["k8s_svc_account"] {
    # lower(input.type) == "container.v1.cluster"
    count([c | r = input.nodePools[j].config; c := 1]) == 0
}

gc_issue["k8s_svc_account"] {
    # lower(input.type) == "container.v1.cluster"
    input.nodePools[j].config.serviceAccount == "default"
}


k8s_svc_account {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_svc_account"]
    not gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account_err = "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access" {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account_miss_err = "Kubernetes Engine Cluster attribute nodePools config missing in the resource" {
    gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access",
    "Policy Description": "This policy identifies Kubernetes Engine Cluster Nodes which have default Service account for Project access. By default, Kubernetes Engine nodes are given the Compute Engine default service account. This account has broad access and more permissions than are required to run your Kubernetes Engine cluster. You should create and use a least privileged service account to run your Kubernetes Engine cluster instead of using the Compute Engine default service account. If you are not creating a separate service account for your nodes, you should limit the scopes of the node service account to reduce the possibility of a privilege escalation in an attack.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-002
#

default k8s_basicauth = null

gc_issue["k8s_basicauth"] {
    # lower(input.type) == "container.v1.cluster"
    count(input.masterAuth.username) > 0
}

gc_issue["k8s_basicauth"] {
    # lower(input.type) == "container.v1.cluster"
    count(input.masterAuth.password) > 0
}

k8s_basicauth {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_basicauth"]
}

k8s_basicauth = false {
    gc_issue["k8s_basicauth"]
}

k8s_basicauth_err = "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled" {
    gc_issue["k8s_basicauth"]
}

k8s_basicauth_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Basic authentication. Basic authentication allows a user to authenticate to the cluster with a username and password. Disabling Basic authentication will prevent attacks like brute force. Authenticate using client certificate or IAM.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-003
#

default k8s_client_cert = null

gc_issue["k8s_client_cert"] {
    # lower(input.type) == "container.v1.cluster"
    not input.masterAuth.clientKey
}

gc_issue["k8s_client_cert"] {
    # lower(input.type) == "container.v1.cluster"
    not input.masterAuth.clientCertificate
}

k8s_client_cert {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_client_cert"]
}

k8s_client_cert = false {
    gc_issue["k8s_client_cert"]
}

k8s_client_cert_err = "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled" {
    gc_issue["k8s_client_cert"]
}

k8s_client_cert_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Client Certificate. A client certificate is a base64-encoded public certificate used by clients to authenticate to the cluster endpoint. Enabling Client Certificate will provide more security to authenticate users to the cluster.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-004
#

default k8s_alias_ip = null

gc_issue["k8s_alias_ip"] {
    # lower(input.type) == "container.v1.cluster"
    not input.ipAllocationPolicy.useIpAliases
}

k8s_alias_ip {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_alias_ip"]
}

k8s_alias_ip = false {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_err = "GCP Kubernetes Engine Clusters have Alias IP disabled" {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alias IP disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Alias IP. Alias IP allows the networking layer to perform anti-spoofing checks to ensure that egress traffic is not sent with arbitrary source IPs. By enabling Alias IPs, Kubernetes Engine clusters can allocate IP addresses from a CIDR block known to Google Cloud Platform. This makes your cluster more scalable and allows your cluster to better interact with other GCP products and entities.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-005
#

default k8s_alpha = null

gc_issue["k8s_alpha"] {
    # lower(input.type) == "container.v1.cluster"
    input.enableKubernetesAlpha
}

k8s_alpha {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_alpha"]
}

k8s_alpha = false {
    gc_issue["k8s_alpha"]
}

k8s_alpha_err = "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled" {
    gc_issue["k8s_alpha"]
}

k8s_alpha_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled alpha cluster. It is recommended to not use alpha clusters or alpha features for production workloads. Alpha clusters expire after 30 days and do not receive security updates. This cluster will not be covered by the Kubernetes Engine SLA.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-006
#

default k8s_http_lbs = null

gc_issue["k8s_http_lbs"] {
    # lower(input.type) == "container.v1.cluster"
    input.addonsConfig.httpLoadBalancing.disabled
}

k8s_http_lbs {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_http_lbs"]
}

k8s_http_lbs = false {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_err = "GCP Kubernetes Engine Clusters have HTTP load balancing disabled" {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have HTTP load balancing disabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have disabled HTTP load balancing. HTTP/HTTPS load balancing provides global load balancing for HTTP/HTTPS requests destined for your instances. Enabling HTTP/HTTPS load balancers will let the Kubernetes Engine to terminate unauthorized HTTP/HTTPS requests and make better context-aware load balancing decisions.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-007
#

default k8s_legacy_abac = null

gc_issue["k8s_legacy_abac"] {
    # lower(input.type) == "container.v1.cluster"
    input.legacyAbac.enabled
}

k8s_legacy_abac {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac = false {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_err = "GCP Kubernetes Engine Clusters have Legacy Authorization enabled" {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Legacy Authorization enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled legacy authorizer. The legacy authorizer in Kubernetes Engine grants broad and statically defined permissions to all cluster users. After legacy authorizer setting is disabled, RBAC can limit permissions for authorized users based on need.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-008
#

default k8s_master_auth_net = null

gc_issue["k8s_master_auth_net"] {
    # lower(input.type) == "container.v1.cluster"
    not input.masterAuthorizedNetworksConfig.enabled
}

k8s_master_auth_net {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net = false {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_err = "GCP Kubernetes Engine Clusters have Master authorized networks disabled" {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Master authorized networks disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Master authorized networks. Enabling Master authorized networks will let the Kubernetes Engine block untrusted non-GCP source IPs from accessing the Kubernetes master through HTTPS.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-009
#

default k8s_net_policy = null

gc_issue["k8s_net_policy"] {
    # lower(input.type) == "container.v1.cluster"
    not input.networkPolicy.enabled
}

k8s_net_policy {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_net_policy"]
}

k8s_net_policy = false {
    gc_issue["k8s_net_policy"]
}

k8s_net_policy_err = "GCP Kubernetes Engine Clusters have Network policy disabled" {
    gc_issue["k8s_net_policy"]
}

k8s_net_policy_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Network policy disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Network policy. A network policy defines how groups of pods are allowed to communicate with each other and other network endpoints. By enabling network policy in a namespace for a pod, it will reject any connections that are not allowed by the network policy.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-010
#

default k8s_logging = null

gc_attribute_absence["k8s_logging"] {
    # lower(input.type) == "container.v1.cluster"
    not input.loggingService
}

gc_issue["k8s_logging"] {
    # lower(input.type) == "container.v1.cluster"
    lower(input.loggingService) == "none"
}

k8s_logging {
    # lower(input.resources[i].type) == "container.v1.cluster"
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
} else = "Kubernetes Engine Cluster attribute loggingService config missing in the resource" {
    gc_attribute_absence["k8s_logging"]
}

k8s_logging_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Stackdriver Logging disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver Logging. Enabling Stackdriver Logging will let the Kubernetes Engine to collect, process, and store your container and system logs in a dedicated persistent data store.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-011
#

default k8s_monitor = null

gc_attribute_absence["k8s_monitor"] {
    # lower(input.type) == "container.v1.cluster"
    not input.monitoringService
}

gc_issue["k8s_monitor"] {
    # lower(input.type) == "container.v1.cluster"
    lower(input.monitoringService) == "none"
}

k8s_monitor {
    # lower(input.resources[i].type) == "container.v1.cluster"
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

k8s_monitor_miss_err = "Kubernetes Engine Cluster attribute monitoringService config missing in the resource" {
    gc_attribute_absence["k8s_monitor"]
}

k8s_monitor_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Stackdriver Monitoring disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver monitoring. Enabling Stackdriver monitoring will let the Kubernetes Engine to monitor signals and build operations in the clusters.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-012
#

default k8s_binary_auth = null

gc_issue["k8s_binary_auth"] {
    # lower(input.type) == "container.v1.cluster"
    not input.binaryAuthorization.enabled
}

k8s_binary_auth {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_binary_auth"]
}

k8s_binary_auth = false {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_err = "GCP Kubernetes Engine Clusters have binary authorization disabled" {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have binary authorization disabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have disabled binary authorization. Binary authorization is a security control that ensures only trusted container images are deployed on GKE clusters. As a best practice, verify images prior to deployment to reduce the risk of running unintended or malicious code in your environment.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-013
#

default k8s_legacy_endpoint = null

gc_issue["k8s_legacy_endpoint"] {
    # lower(input.type) == "container.v1.cluster"
    lower(input.nodeConfig.metadata["disable-legacy-endpoints"]) == "true"
}

gc_issue["k8s_legacy_endpoint"] {
    # lower(input.type) == "container.v1.cluster"
    input.nodeConfig.metadata["disable-legacy-endpoints"] == true
}

k8s_legacy_endpoint {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint = false {
    gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_err = "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled" {
    gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have legacy compute engine metadata endpoints enabled. Because GKE uses instance metadata to configure node VMs, some of this metadata is potentially sensitive and should be protected from workloads running on the cluster. Legacy metadata APIs expose the Compute Engine's instance metadata of server endpoints. As a best practice, disable legacy API and use v1 APIs to restrict a potential attacker from retrieving instance metadata.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-014
#

default k8s_pod_security = null

gc_issue["k8s_pod_security"] {
    # lower(input.type) == "container.v1.cluster"
    not input.podSecurityPolicyConfig.enabled
}

k8s_pod_security {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_pod_security"]
}

k8s_pod_security = false {
    gc_issue["k8s_pod_security"]
}

k8s_pod_security_err = "GCP Kubernetes Engine Clusters have pod security policy disabled" {
    gc_issue["k8s_pod_security"]
}

k8s_pod_security_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have pod security policy disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have pod security policy disabled. The Pod Security Policy defines a set of conditions that pods must meet to be accepted by the cluster; when a request to create or update a pod does not meet the conditions in the pod security policy, that request is rejected and an error is returned.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-015
#

default k8s_egress_metering = null

gc_issue["k8s_egress_metering"] {
    # lower(input.type) == "container.v1.cluster"
    not input.resourceUsageExportConfig.enableNetworkEgressMetering
}

k8s_egress_metering {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_egress_metering"]
}

k8s_egress_metering = false {
    gc_issue["k8s_egress_metering"]
}

k8s_egress_metering_err = "GCP Kubernetes Engine Clusters not configured with network traffic egress metering" {
    gc_issue["k8s_egress_metering"]
}

k8s_egress_metering_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with network traffic egress metering",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with network traffic egress metering. When network traffic egress metering enabled, deployed DaemonSet pod meters network egress traffic by collecting data from the conntrack table, and exports the metered metrics to the specified destination. It is recommended to use, network egress metering so that you will be having data and track over monitored network traffic.<br><br>NOTE: Measuring network egress requires a network metering agent (NMA) running on each node. The NMA runs as a privileged pod, consumes some resources on the node (CPU, memory, and disk space), and enables the nf_conntrack_acct sysctl flag on the kernel (for connection tracking flow accounting). If you are comfortable with these caveats, you can enable network egress tracking for use with GKE usage metering.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-016
#

default k8s_private = null

gc_issue["k8s_private"] {
    # lower(input.type) == "container.v1.cluster"
    not input.privateClusterConfig
}

k8s_private {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_private"]
}

k8s_private = false {
    gc_issue["k8s_private"]
}

k8s_private_err = "GCP Kubernetes Engine Clusters not configured with private cluster" {
    gc_issue["k8s_private"]
}

k8s_private_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-016",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private cluster",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with the Private cluster. Private cluster makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-017
#

default k8s_private_node = null

gc_issue["k8s_private_node"] {
    # lower(input.type) == "container.v1.cluster"
    not input.privateClusterConfig.enablePrivateNodes
}

k8s_private_node {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_private_node"]
}

k8s_private_node = false {
    gc_issue["k8s_private_node"]
}

k8s_private_node_err = "GCP Kubernetes Engine Clusters not configured with private nodes feature" {
    gc_issue["k8s_private_node"]
}

k8s_private_node_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-017",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private nodes feature",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) Clusters which are not configured with the private nodes feature. Private nodes feature makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-018
#

default k8s_node_image = null

gc_attribute_absence["k8s_node_image"] {
    # lower(input.type) == "container.v1.cluster"
    not input.nodeConfig.imageType
    nodePools := input.nodePools[j]
    not nodePools.config.imageType
}

gc_issue["k8s_node_image"] {
    # lower(input.type) == "container.v1.cluster"
    not startswith(lower(input.nodeConfig.imageType), "cos")
}

gc_issue["k8s_node_image"] {
    # lower(input.type) == "container.v1.cluster"
    nodePools := input.nodePools[j]
    not startswith(lower(nodePools.config.imageType), "cos")
}

k8s_node_image {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_node_image"]
    not gc_attribute_absence["k8s_node_image"]
}

k8s_node_image = false {
    gc_issue["k8s_node_image"]
}

k8s_node_image = false {
    gc_attribute_absence["k8s_node_image"]
}

k8s_node_image_err = "GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image" {
    gc_issue["k8s_node_image"]
}

k8s_node_image_miss_err = "Kubernetes Engine Cluster attribute imageType config missing in the resource" {
    gc_attribute_absence["k8s_node_image"]
}

k8s_node_image_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-018",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which do not have a container-optimized operating system for node image. Container-Optimized OS is an operating system image for your Compute Engine VMs that is optimized for running Docker containers. By using Container-Optimized OS for node image, you can bring up your Docker containers on Google Cloud Platform quickly, efficiently, and securely. The Container-Optimized OS node image is based on a recent version of the Linux kernel and is optimized to enhance node security. It is also regularly updated with features, security fixes, and patches. The Container-Optimized OS image provides better support, security, and stability than other images.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-019
#

default k8s_network = null

gc_issue["k8s_network"] {
    # lower(input.type) == "container.v1.cluster"
    not input.network
}

gc_issue["k8s_network"] {
    # lower(input.type) == "container.v1.cluster"
    lower(input.network) == "default"
}

k8s_network {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_network"]
}

k8s_network = false {
    gc_issue["k8s_network"]
}

k8s_network_err = "GCP Kubernetes Engine Clusters using the default network" {
    gc_issue["k8s_network"]
}

k8s_network_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-019",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters using the default network",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that are configured to use the default network. Because GKE uses this network when creating routes and firewalls for the cluster, as a best practice define a network configuration that meets your security and networking requirements for ingress and egress traffic, instead of using the default network.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-020
#

default k8s_dashboard = null

gc_issue["k8s_dashboard"] {
    # lower(input.type) == "container.v1.cluster"
    not input.addonsConfig.kubernetesDashboard.disabled
}

k8s_dashboard {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_dashboard"]
}

k8s_dashboard = false {
    gc_issue["k8s_dashboard"]
}

k8s_dashboard_err = "GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled" {
    gc_issue["k8s_dashboard"]
}

k8s_dashboard_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-020",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Kubernetes web UI/Dashboard. Since all the data is being transmitted over HTTP protocol, disabling Kubernetes web UI/Dashboard will protect the data from sniffers on the same network.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-021
#

default k8s_labels = null

gc_issue["k8s_labels"] {
    # lower(input.type) == "container.v1.cluster"
    not input.resourceLabels
}

gc_issue["k8s_labels"] {
    # lower(input.type) == "container.v1.cluster"
    count(input.resourceLabels) == 0
}

k8s_labels {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_labels"]
}

k8s_labels = false {
    gc_issue["k8s_labels"]
}

k8s_labels_err = "GCP Kubernetes Engine Clusters without any label information" {
    gc_issue["k8s_labels"]
}

k8s_labels_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-021",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters without any label information",
    "Policy Description": "This policy identifies all Kubernetes Engine Clusters which do not have labels. Having a cluster label helps you identify and categorize Kubernetes clusters.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-022
#

default k8s_db_encrypt = null

gc_attribute_absence["k8s_db_encrypt"] {
    # lower(input.type) == "container.v1.cluster"
    not input.databaseEncryption
}

gc_issue["k8s_db_encrypt"] {
    # lower(input.type) == "container.v1.cluster"
    lower(input.databaseEncryption.state) != "encrypted"
}

gc_issue["k8s_db_encrypt"] {
    # lower(input.type) == "container.v1.cluster"
    not input.databaseEncryption.keyName
}

gc_issue["k8s_db_encrypt"] {
    # lower(input.type) == "container.v1.cluster"
    count(input.databaseEncryption.keyName) == 0
}

k8s_db_encrypt {
    # lower(input.resources[i].type) == "container.v1.cluster"
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

k8s_db_encrypt_miss_err = "Kubernetes Engine Cluster attribute databaseEncryption config missing in the resource" {
    gc_attribute_absence["k8s_db_encrypt"]
}

k8s_db_encrypt_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-022",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes cluster Application-layer Secrets not encrypted",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etcd.<br><br>This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-023
#

default k8s_intra_node = null

gc_issue["k8s_intra_node"] {
    # lower(input.type) == "container.v1.cluster"
    not input.networkConfig.enableIntraNodeVisibility
}

k8s_intra_node {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_intra_node"]
}

k8s_intra_node = false {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_err = "GCP Kubernetes cluster intra-node visibility disabled" {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-023",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes cluster intra-node visibility disabled",
    "Policy Description": "With Intranode Visibility, all network traffic in your cluster is seen by the Google Cloud Platform network. This means you can see flow logs for all traffic between Pods, including traffic between Pods on the same node. And you can create firewall rules that apply to all traffic between Pods.<br><br>This policy checks your cluster's intra-node visibility feature and generates an alert if it's disabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-024
#

default k8s_istio = null

gc_issue["k8s_istio"] {
    # lower(input.type) == "container.v1.cluster"
    not input.addonsConfig.istioConfig.disabled
}

k8s_istio {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_istio"]
}

k8s_istio = false {
    gc_issue["k8s_istio"]
}

k8s_istio_err = "GCP Kubernetes cluster istioConfig not enabled" {
    gc_issue["k8s_istio"]
}

k8s_istio_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-024",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes cluster istioConfig not enabled",
    "Policy Description": "Istio is an open service mesh that provides a uniform way to connect, manage, and secure microservices. It supports managing traffic flows between services, enforcing access policies, and aggregating telemetry data, all without requiring changes to the microservice code.<br><br>This policy checks your cluster for the Istio add-on feature and alerts if it is not enabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-025
#

default k8s_zones = null

gc_issue["k8s_zones"] {
    # lower(input.type) == "container.v1.cluster"
    input.zone
    count(input.locations) < 3
}

k8s_zones {
    # lower(input.resources[i].type) == "container.v1.cluster"
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
    "Policy Code": "PR-GCP-CLD-CLT-025",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes cluster not in redundant zones",
    "Policy Description": "Putting resources in different zones in a region provides isolation from many types of infrastructure, hardware, and software failures.<br><br>This policy alerts if your cluster is not located in at least 3 zones.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-CLD-CLT-026
#

default k8s_auto_upgrade = null

gc_attribute_absence["k8s_auto_upgrade"] {
    # lower(input.type) == "container.v1.cluster"
    not input.currentNodeCount
}

gc_issue["k8s_auto_upgrade"] {
    # lower(input.type) == "container.v1.cluster"
    to_number(input.currentNodeCount) < 3
    input.nodePools[j].management.autoUpgrade
}

gc_issue["k8s_auto_upgrade"] {
    # lower(input.type) == "container.v1.cluster"
    not input.databaseEncryption.keyName
}

gc_issue["k8s_auto_upgrade"] {
    # lower(input.type) == "container.v1.cluster"
    count(input.databaseEncryption.keyName) == 0
}

k8s_auto_upgrade {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_auto_upgrade"]
    not gc_attribute_absence["k8s_auto_upgrade"]
}

k8s_auto_upgrade = false {
    gc_issue["k8s_auto_upgrade"]
}

k8s_auto_upgrade = false {
    gc_attribute_absence["k8s_auto_upgrade"]
}

k8s_auto_upgrade_err = "GCP Kubernetes cluster size contains less than 3 nodes with auto upgrade enabled" {
    gc_issue["k8s_auto_upgrade"]
}

k8s_auto_upgrade_miss_err = "Kubernetes Engine Cluster attribute currentNodeCount config missing in the resource" {
    gc_attribute_absence["k8s_auto_upgrade"]
}

k8s_auto_upgrade_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-026",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Kubernetes cluster size contains less than 3 nodes with auto upgrade enabled",
    "Policy Description": "Ensure your Kubernetes cluster size contains 3 or more nodes. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pools and alerts if there are fewer than 3 nodes in a pool.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}


#
# PR-GCP-CLD-CLT-027
#

default k8s_channel = null

gc_issue["k8s_channel"] {
    # lower(input.type) == "container.v1.cluster"
    not input.releaseChannel.channel
}

k8s_channel {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_channel"]
}

k8s_channel = false {
    gc_issue["k8s_channel"]
}

k8s_channel_err = "Ensure GCP Kubernetes Engine cluster using Release Channel for version management" {
    gc_issue["k8s_channel"]
}

k8s_channel_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-027",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes Engine cluster using Release Channel for version management",
    "Policy Description": "This policy identifies GCP Kubernetes Engine clusters that are not using Release Channel for version management. Subscribing to a specific release channel reduces version management complexity. \n\nThe Regular release channel upgrades every few weeks and is for production users who need features not yet offered in the Stable channel. These versions have passed internal validation, but don't have enough historical data to guarantee their stability. Known issues generally have known workarounds.\n\nThe Stable release channel upgrades every few months and is for production users who need stability above all else, and for whom frequent upgrades are too risky. These versions have passed internal validation and have been shown to be stable and reliable in production, based on the observed performance of those clusters.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/Shared.Types/ReleaseChannel"
}


#
# PR-GCP-CLD-CLT-028
#

default k8s_workload = null

gc_issue["k8s_workload"] {
    # lower(input.type) == "container.v1.cluster"
    lower(input.status) == "running"
    not startswith(lower(input.resourceLabels["goog-composer-version"]), "composer-1")
    not input.workloadIdentityConfig
}

k8s_workload {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_workload"]
}

k8s_workload = false {
    gc_issue["k8s_workload"]
}

k8s_workload_err = "Ensure GCP Kubernetes Engine cluster workload identity is enabled" {
    gc_issue["k8s_workload"]
}

k8s_workload_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-028",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes Engine cluster workload identity is enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine clusters for which workload identity is disabled. Manual approaches for authenticating Kubernetes workloads violates the principle of least privilege on a multi-tenanted node when one pod needs to have access to a service, but every other pod on the node that uses the service account does not. Enabling Workload Identity manages the distribution and rotation of Service account keys for the workloads to use.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeConfig"
}


#
# PR-GCP-CLD-CLT-029
#

default k8s_shield_node = null

gc_issue["k8s_shield_node"] {
    # lower(input.type) == "container.v1.cluster"
    lower(input.shieldedNodes) == "false"
}

gc_issue["k8s_shield_node"] {
    # lower(input.type) == "container.v1.cluster"
    not input.shieldedNodes
}

k8s_shield_node {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_shield_node"]
}

k8s_shield_node = false {
    gc_issue["k8s_shield_node"]
}

k8s_shield_node_err = "Ensure GCP Kubernetes cluster Shielded GKE Nodes feature enabled" {
    gc_issue["k8s_shield_node"]
}

k8s_shield_node_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-029",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes cluster Shielded GKE Nodes feature enabled",
    "Policy Description": "This policy identifies GCP Kubernetes clusters for which the Shielded GKE Nodes feature is not enabled. Shielded GKE nodes protect clusters against boot- or kernel-level malware or rootkits\nwhich persist beyond infected OS. It is recommended to enable Shielded GKE Nodes for all the Kubernetes clusters.\n\nFMI: https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster.ShieldedNodes"
}


#
# PR-GCP-CLD-CLT-030
#

default k8s_node_autorepair = null

gc_issue["k8s_node_autorepair"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    not node_pool.management.autoRepair
}

gc_issue["k8s_node_autorepair"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    lower(node_pool.management.autoRepair) == "false"
}

k8s_node_autorepair {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_node_autorepair"]
}

k8s_node_autorepair = false {
    gc_issue["k8s_node_autorepair"]
}

k8s_node_autorepair_err = "Ensure GCP Kubernetes cluster node auto-repair configuration enabled" {
    gc_issue["k8s_node_autorepair"]
}

k8s_node_autorepair_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-030",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes cluster node auto-repair configuration enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster nodes with auto-repair configuration disabled. GKE's node auto-repair feature helps you keep the nodes in your cluster in a healthy, running state. When enabled, GKE makes periodic checks on the health state of each node in your cluster. If a node fails consecutive health checks over an extended time period, GKE initiates a repair process for that node.\n\nFMI: https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}


#
# PR-GCP-CLD-CLT-031
#

default k8s_node_autoupgrade = null

gc_issue["k8s_node_autoupgrade"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    not node_pool.management.autoUpgrade
}

gc_issue["k8s_node_autoupgrade"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    lower(node_pool.management.autoUpgrade) == "false"
}

k8s_node_autoupgrade {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_node_autoupgrade"]
}

k8s_node_autoupgrade = false {
    gc_issue["k8s_node_autoupgrade"]
}

k8s_node_autoupgrade_err = "Ensure GCP Kubernetes cluster node auto-upgrade configuration enabled" {
    gc_issue["k8s_node_autoupgrade"]
}

k8s_node_autoupgrade_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-031",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes cluster node auto-upgrade configuration enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster nodes with auto-upgrade configuration disabled. Node auto-upgrades help you keep the nodes in your cluster up to date with the cluster master version when your master is updated on your behalf. When you create a new cluster using Google Cloud Platform Console, node auto-upgrade is enabled by default.\n\nFMI: https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}


#
# PR-GCP-CLD-CLT-032
#

default k8s_secure_boot = null

gc_issue["k8s_secure_boot"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    not node_pool.config.shieldedInstanceConfig.enableSecureBoot
}

gc_issue["k8s_secure_boot"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    lower(node_pool.config.shieldedInstanceConfig.enableSecureBoot) == "false"
}

k8s_secure_boot {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_secure_boot"]
}

k8s_secure_boot = false {
    gc_issue["k8s_secure_boot"]
}

k8s_secure_boot_err = "Ensure GCP Kubernetes cluster shielded GKE node with Secure Boot enabled" {
    gc_issue["k8s_secure_boot"]
}

k8s_secure_boot_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-032",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes cluster shielded GKE node with Secure Boot enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster shielded GKE nodes with Secure Boot disabled. An attacker may seek to alter boot components to persist malware or rootkits during system initialization. It is recommended to enable Secure Boot for Shielded GKE Nodes to verify the digital signature of node boot components.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}



#
# PR-GCP-CLD-CLT-033
#

default k8s_integrity_monitor = null

gc_issue["k8s_integrity_monitor"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    not node_pool.config.shieldedInstanceConfig.enableIntegrityMonitoring
}

gc_issue["k8s_integrity_monitor"] {
    # lower(input.type) == "container.v1.cluster"
    node_pool := input.nodePools[_]
    lower(node_pool.config.shieldedInstanceConfig.enableIntegrityMonitoring) == "false"
}

k8s_integrity_monitor {
    # lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_integrity_monitor"]
}

k8s_integrity_monitor = false {
    gc_issue["k8s_integrity_monitor"]
}

k8s_integrity_monitor_err = "Ensure GCP Kubernetes cluster shielded GKE node with integrity monitoring enabled" {
    gc_issue["k8s_integrity_monitor"]
}

k8s_integrity_monitor_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-033",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes cluster shielded GKE node with integrity monitoring enabled",
    "Policy Description": "This policy identifies GCP Kubernetes cluster shielded GKE nodes that are not enabled with Integrity Monitoring. Integrity Monitoring provides active alerting for Shielded GKE nodes which allows administrators to respond to integrity failures and prevent compromised nodes from being deployed into the cluster.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/NodeManagement"
}


#
# PR-GCP-CLD-CLT-034 
# 
# "container.v1.cluster"

default secret_encrypted = null

gc_issue["secret_encrypted"] {
    upper(input.databaseEncryption.state) == "DECRYPTED"
}

secret_encrypted{
    not gc_issue["secret_encrypted"]
}

secret_encrypted = false{
    gc_issue["secret_encrypted"]
}

secret_encrypted_err = "Ensure GCP Kubernetes cluster Application-layer Secrets are decrypted."{
    gc_issue["secret_encrypted"]
}

secret_encrypted_metadata := {
    "Policy Code": "PR-GCP-CLD-CLT-034",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes cluster Application-layer Secrets are decrypted.",
    "Policy Description": "This policy established Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etc. This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}


#
# PR-GCP-CLD-CLT-035
#
# "container.v1.cluster"

default private_endpoint_disabled = true

gc_issue["private_endpoint_disabled"] {
    upper(input.status) == "RUNNING"
    has_property(input, "privateClusterConfig")
    not has_property(input.privateClusterConfig, "enablePrivateEndpoint")
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
    "Policy Code": "PR-GCP-CLD-CLT-035",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure GCP Kubernetes Engine private cluster has private endpoint disabled.",
    "Policy Description": "This policy finds GCP Kubernetes Engine private clusters with private endpoint disabled. A public endpoint might expose the current cluster and Kubernetes API version and an attacker may be able to determine whether it is vulnerable to an attack. Unless required, disabling the public endpoint will help prevent such threats, and require the attacker to be on the master's VPC network to perform any attack on the Kubernetes API. It is recommended to enable the private endpoint and disable public access on Kubernetes clusters.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}