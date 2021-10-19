package rule

# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters

#
# PR-GCP-GDF-CLT-001
#

default k8s_svc_account = null

gc_attribute_absence["k8s_svc_account"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count([c | r = resource.properties.nodePools[j].config; c := 1]) == 0
}

source_path[{"k8s_svc_account": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count([c | r = resource.properties.nodePools[j].config; c := 1]) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "nodePools"]
        ],
    }
}

gc_issue["k8s_svc_account"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.nodePools[j].config.serviceAccount == "default"
}

source_path[{"k8s_svc_account": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.nodePools[j].config.serviceAccount == "default"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "nodePools", j, "config", "serviceAccount"]
        ],
    }
}

k8s_svc_account {
    lower(input.resources[i].type) == "container.v1.cluster"
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
    "Policy Code": "PR-GCP-GDF-CLT-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access",
    "Policy Description": "This policy identifies Kubernetes Engine Cluster Nodes which have default Service account for Project access. By default, Kubernetes Engine nodes are given the Compute Engine default service account. This account has broad access and more permissions than are required to run your Kubernetes Engine cluster. You should create and use a least privileged service account to run your Kubernetes Engine cluster instead of using the Compute Engine default service account. If you are not creating a separate service account for your nodes, you should limit the scopes of the node service account to reduce the possibility of a privilege escalation in an attack.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-002
#

default k8s_basicauth = null

gc_issue["k8s_basicauth"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.masterAuth.username) > 0
}

source_path[{"k8s_basicauth": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.masterAuth.username) > 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "masterAuth", "username"]
        ],
    }
}

gc_issue["k8s_basicauth"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.masterAuth.password) > 0
}

source_path[{"k8s_basicauth": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.masterAuth.password) > 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "masterAuth", "password"]
        ],
    }
}

k8s_basicauth {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_basicauth"]
}

k8s_basicauth = false {
    gc_issue["k8s_basicauth"]
}

k8s_basicauth_err = "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled" {
    gc_issue["k8s_basicauth"]
}

k8s_basicauth_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Basic authentication. Basic authentication allows a user to authenticate to the cluster with a username and password. Disabling Basic authentication will prevent attacks like brute force. Authenticate using client certificate or IAM.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-003
#

default k8s_client_cert = null

gc_issue["k8s_client_cert"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuth.clientKey
}

source_path[{"k8s_client_cert": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuth.clientKey
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "masterAuth", "clientKey"]
        ],
    }
}

gc_issue["k8s_client_cert"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuth.clientCertificate
}

source_path[{"k8s_client_cert": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuth.clientCertificate
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "masterAuth", "clientCertificate"]
        ],
    }
}

k8s_client_cert {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_client_cert"]
}

k8s_client_cert = false {
    gc_issue["k8s_client_cert"]
}

k8s_client_cert_err = "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled" {
    gc_issue["k8s_client_cert"]
}

k8s_client_cert_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Client Certificate. A client certificate is a base64-encoded public certificate used by clients to authenticate to the cluster endpoint. Enabling Client Certificate will provide more security to authenticate users to the cluster.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-004
#

default k8s_alias_ip = null

gc_issue["k8s_alias_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.ipAllocationPolicy.useIpAliases
}

source_path[{"k8s_alias_ip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.ipAllocationPolicy.useIpAliases
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "ipAllocationPolicy", "useIpAliases"]
        ],
    }
}

k8s_alias_ip {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_alias_ip"]
}

k8s_alias_ip = false {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_err = "GCP Kubernetes Engine Clusters have Alias IP disabled" {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alias IP disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Alias IP. Alias IP allows the networking layer to perform anti-spoofing checks to ensure that egress traffic is not sent with arbitrary source IPs. By enabling Alias IPs, Kubernetes Engine clusters can allocate IP addresses from a CIDR block known to Google Cloud Platform. This makes your cluster more scalable and allows your cluster to better interact with other GCP products and entities.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-005
#

default k8s_alpha = null

gc_issue["k8s_alpha"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.enableKubernetesAlpha
}

source_path[{"k8s_alpha": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.enableKubernetesAlpha
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "enableKubernetesAlpha"]
        ],
    }
}

k8s_alpha {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_alpha"]
}

k8s_alpha = false {
    gc_issue["k8s_alpha"]
}

k8s_alpha_err = "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled" {
    gc_issue["k8s_alpha"]
}

k8s_alpha_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled alpha cluster. It is recommended to not use alpha clusters or alpha features for production workloads. Alpha clusters expire after 30 days and do not receive security updates. This cluster will not be covered by the Kubernetes Engine SLA.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-006
#

default k8s_http_lbs = null

gc_issue["k8s_http_lbs"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.addonsConfig.httpLoadBalancing.disabled
}

source_path[{"k8s_http_lbs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.addonsConfig.httpLoadBalancing.disabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "addonsConfig", "httpLoadBalancing", "disabled"]
        ],
    }
}

k8s_http_lbs {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_http_lbs"]
}

k8s_http_lbs = false {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_err = "GCP Kubernetes Engine Clusters have HTTP load balancing disabled" {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have HTTP load balancing disabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have disabled HTTP load balancing. HTTP/HTTPS load balancing provides global load balancing for HTTP/HTTPS requests destined for your instances. Enabling HTTP/HTTPS load balancers will let the Kubernetes Engine to terminate unauthorized HTTP/HTTPS requests and make better context-aware load balancing decisions.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-007
#

default k8s_legacy_abac = null

gc_issue["k8s_legacy_abac"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.legacyAbac.enabled
}

source_path[{"k8s_legacy_abac": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.legacyAbac.enabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "legacyAbac", "enabled"]
        ],
    }
}

k8s_legacy_abac {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac = false {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_err = "GCP Kubernetes Engine Clusters have Legacy Authorization enabled" {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have Legacy Authorization enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled legacy authorizer. The legacy authorizer in Kubernetes Engine grants broad and statically defined permissions to all cluster users. After legacy authorizer setting is disabled, RBAC can limit permissions for authorized users based on need.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-008
#

default k8s_master_auth_net = null

gc_issue["k8s_master_auth_net"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuthorizedNetworksConfig.enabled
}

source_path[{"k8s_master_auth_net": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.legacyAbac.enabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "masterAuthorizedNetworksConfig", "enabled"]
        ],
    }
}

k8s_master_auth_net {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net = false {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_err = "GCP Kubernetes Engine Clusters have Master authorized networks disabled" {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have Master authorized networks disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Master authorized networks. Enabling Master authorized networks will let the Kubernetes Engine block untrusted non-GCP source IPs from accessing the Kubernetes master through HTTPS.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-009
#

default k8s_net_policy = null

gc_issue["k8s_net_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.networkPolicy.enabled
}

source_path[{"k8s_net_policy": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.networkPolicy.enabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "networkPolicy", "enabled"]
        ],
    }
}

k8s_net_policy {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_net_policy"]
}

k8s_net_policy = false {
    gc_issue["k8s_net_policy"]
}

k8s_net_policy_err = "GCP Kubernetes Engine Clusters have Network policy disabled" {
    gc_issue["k8s_net_policy"]
}

k8s_net_policy_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have Network policy disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Network policy. A network policy defines how groups of pods are allowed to communicate with each other and other network endpoints. By enabling network policy in a namespace for a pod, it will reject any connections that are not allowed by the network policy.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-010
#

default k8s_logging = null

gc_attribute_absence["k8s_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.loggingService
}

source_path[{"k8s_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.loggingService
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "loggingService"]
        ],
    }
}

gc_issue["k8s_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.loggingService) == "none"
}

source_path[{"k8s_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.loggingService) == "none"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "loggingService"]
        ],
    }
}

k8s_logging {
    lower(input.resources[i].type) == "container.v1.cluster"
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

k8s_logging_miss_err = "Kubernetes Engine Cluster attribute loggingService config missing in the resource" {
    gc_attribute_absence["k8s_logging"]
}

k8s_logging_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have Stackdriver Logging disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver Logging. Enabling Stackdriver Logging will let the Kubernetes Engine to collect, process, and store your container and system logs in a dedicated persistent data store.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-011
#

default k8s_monitor = null

gc_attribute_absence["k8s_monitor"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.monitoringService
}

source_path[{"k8s_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.monitoringService
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "monitoringService"]
        ],
    }
}

gc_issue["k8s_monitor"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.monitoringService) == "none"
}

source_path[{"k8s_monitor": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.monitoringService) == "none"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "monitoringService"]
        ],
    }
}

k8s_monitor {
    lower(input.resources[i].type) == "container.v1.cluster"
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
    "Policy Code": "PR-GCP-GDF-CLT-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have Stackdriver Monitoring disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver monitoring. Enabling Stackdriver monitoring will let the Kubernetes Engine to monitor signals and build operations in the clusters.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-012
#

default k8s_binary_auth = null

gc_issue["k8s_binary_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.binaryAuthorization.enabled
}

source_path[{"k8s_binary_auth": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.binaryAuthorization.enabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "binaryAuthorization", "enabled"]
        ],
    }
}

k8s_binary_auth {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_binary_auth"]
}

k8s_binary_auth = false {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_err = "GCP Kubernetes Engine Clusters have binary authorization disabled" {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have binary authorization disabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have disabled binary authorization. Binary authorization is a security control that ensures only trusted container images are deployed on GKE clusters. As a best practice, verify images prior to deployment to reduce the risk of running unintended or malicious code in your environment.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-013
#

default k8s_legacy_endpoint = null

gc_issue["k8s_legacy_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.nodeConfig.metadata["disable-legacy-endpoints"]
}

source_path[{"k8s_legacy_endpoint": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.nodeConfig.metadata["disable-legacy-endpoints"]
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "nodeConfig", "metadata", "disable-legacy-endpoints"]
        ],
    }
}

k8s_legacy_endpoint {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint = false {
    gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_err = "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled" {
    gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have legacy compute engine metadata endpoints enabled. Because GKE uses instance metadata to configure node VMs, some of this metadata is potentially sensitive and should be protected from workloads running on the cluster. Legacy metadata APIs expose the Compute Engine's instance metadata of server endpoints. As a best practice, disable legacy API and use v1 APIs to restrict a potential attacker from retrieving instance metadata.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-014
#

default k8s_pod_security = null

gc_issue["k8s_pod_security"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.podSecurityPolicyConfig.enabled
}

source_path[{"k8s_pod_security": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.podSecurityPolicyConfig.enabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "podSecurityPolicyConfig", "enabled"]
        ],
    }
}

k8s_pod_security {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_pod_security"]
}

k8s_pod_security = false {
    gc_issue["k8s_pod_security"]
}

k8s_pod_security_err = "GCP Kubernetes Engine Clusters have pod security policy disabled" {
    gc_issue["k8s_pod_security"]
}

k8s_pod_security_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters have pod security policy disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have pod security policy disabled. The Pod Security Policy defines a set of conditions that pods must meet to be accepted by the cluster; when a request to create or update a pod does not meet the conditions in the pod security policy, that request is rejected and an error is returned.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-015
#

default k8s_egress_metering = null

gc_issue["k8s_egress_metering"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.resourceUsageExportConfig.enableNetworkEgressMetering
}

source_path[{"k8s_egress_metering": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.resourceUsageExportConfig.enableNetworkEgressMetering
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "resourceUsageExportConfig", "enableNetworkEgressMetering"]
        ],
    }
}

k8s_egress_metering {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_egress_metering"]
}

k8s_egress_metering = false {
    gc_issue["k8s_egress_metering"]
}

k8s_egress_metering_err = "GCP Kubernetes Engine Clusters not configured with network traffic egress metering" {
    gc_issue["k8s_egress_metering"]
}

k8s_egress_metering_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with network traffic egress metering",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with network traffic egress metering. When network traffic egress metering enabled, deployed DaemonSet pod meters network egress traffic by collecting data from the conntrack table, and exports the metered metrics to the specified destination. It is recommended to use, network egress metering so that you will be having data and track over monitored network traffic._x005F_x000D_ _x005F_x000D_ NOTE: Measuring network egress requires a network metering agent (NMA) running on each node. The NMA runs as a privileged pod, consumes some resources on the node (CPU, memory, and disk space), and enables the nf_conntrack_acct sysctl flag on the kernel (for connection tracking flow accounting). If you are comfortable with these caveats, you can enable network egress tracking for use with GKE usage metering.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-016
#

default k8s_private = null

gc_issue["k8s_private"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.privateClusterConfig
}

source_path[{"k8s_private": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.privateClusterConfig
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "privateClusterConfig"]
        ],
    }
}

k8s_private {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_private"]
}

k8s_private = false {
    gc_issue["k8s_private"]
}

k8s_private_err = "GCP Kubernetes Engine Clusters not configured with private cluster" {
    gc_issue["k8s_private"]
}

k8s_private_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-016",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private cluster",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which are not configured with the Private cluster. Private cluster makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-017
#

default k8s_private_node = null

gc_issue["k8s_private_node"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.privateClusterConfig.enablePrivateNodes
}

source_path[{"k8s_private_node": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.privateClusterConfig.enablePrivateNodes
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "privateClusterConfig", "enablePrivateNodes"]
        ],
    }
}

k8s_private_node {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_private_node"]
}

k8s_private_node = false {
    gc_issue["k8s_private_node"]
}

k8s_private_node_err = "GCP Kubernetes Engine Clusters not configured with private nodes feature" {
    gc_issue["k8s_private_node"]
}

k8s_private_node_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-017",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private nodes feature",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) Clusters which are not configured with the private nodes feature. Private nodes feature makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-018
#

default k8s_node_image = null

gc_attribute_absence["k8s_node_image"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.nodeConfig.imageType
    nodePools := resource.properties.nodePools[j]
    not nodePools.config.imageType
}

source_path[{"k8s_node_image": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.nodeConfig.imageType
    nodePools := resource.properties.nodePools[j]
    not nodePools.config.imageType
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "nodePools", j, "config", "imageType"]
        ],
    }
}

gc_issue["k8s_node_image"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not startswith(lower(resource.properties.nodeConfig.imageType), "cos")
}

source_path[{"k8s_node_image": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not startswith(lower(resource.properties.nodeConfig.imageType), "cos")
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "nodeConfig", "imageType"]
        ],
    }
}

gc_issue["k8s_node_image"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    nodePools := resource.properties.nodePools[j]
    not startswith(lower(nodePools.config.imageType), "cos")
}

source_path[{"k8s_node_image": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    nodePools := resource.properties.nodePools[j]
    not startswith(lower(nodePools.config.imageType), "cos")
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "nodePools", j, "config", "imageType"]
        ],
    }
}

k8s_node_image {
    lower(input.resources[i].type) == "container.v1.cluster"
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
    "Policy Code": "PR-GCP-GDF-CLT-018",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which do not have a container-optimized operating system for node image. Container-Optimized OS is an operating system image for your Compute Engine VMs that is optimized for running Docker containers. By using Container-Optimized OS for node image, you can bring up your Docker containers on Google Cloud Platform quickly, efficiently, and securely. The Container-Optimized OS node image is based on a recent version of the Linux kernel and is optimized to enhance node security. It is also regularly updated with features, security fixes, and patches. The Container-Optimized OS image provides better support, security, and stability than other images.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-019
#

default k8s_network = null

gc_issue["k8s_network"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.network
}

source_path[{"k8s_network": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.network
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "network"]
        ],
    }
}

gc_issue["k8s_network"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.network) == "default"
}

source_path[{"k8s_network": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.network) == "default"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "network"]
        ],
    }
}

k8s_network {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_network"]
}

k8s_network = false {
    gc_issue["k8s_network"]
}

k8s_network_err = "GCP Kubernetes Engine Clusters using the default network" {
    gc_issue["k8s_network"]
}

k8s_network_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-019",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters using the default network",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that are configured to use the default network. Because GKE uses this network when creating routes and firewalls for the cluster, as a best practice define a network configuration that meets your security and networking requirements for ingress and egress traffic, instead of using the default network.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-020
#

default k8s_dashboard = null

gc_issue["k8s_dashboard"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.addonsConfig.kubernetesDashboard.disabled
}

source_path[{"k8s_dashboard": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.addonsConfig.kubernetesDashboard.disabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "addonsConfig", "kubernetesDashboard", "disabled"]
        ],
    }
}

k8s_dashboard {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_dashboard"]
}

k8s_dashboard = false {
    gc_issue["k8s_dashboard"]
}

k8s_dashboard_err = "GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled" {
    gc_issue["k8s_dashboard"]
}

k8s_dashboard_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-020",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Kubernetes web UI/Dashboard. Since all the data is being transmitted over HTTP protocol, disabling Kubernetes web UI/Dashboard will protect the data from sniffers on the same network.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-021
#

default k8s_labels = null

gc_issue["k8s_labels"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.resourceLabels
}

source_path[{"k8s_labels": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.resourceLabels
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "resourceLabels"]
        ],
    }
}

gc_issue["k8s_labels"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.resourceLabels) == 0
}

source_path[{"k8s_labels": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.resourceLabels) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "resourceLabels"]
        ],
    }
}

k8s_labels {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_labels"]
}

k8s_labels = false {
    gc_issue["k8s_labels"]
}

k8s_labels_err = "GCP Kubernetes Engine Clusters without any label information" {
    gc_issue["k8s_labels"]
}

k8s_labels_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-021",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes Engine Clusters without any label information",
    "Policy Description": "This policy identifies all Kubernetes Engine Clusters which do not have labels. Having a cluster label helps you identify and categorize Kubernetes clusters.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-022
#

default k8s_db_encrypt = null

gc_attribute_absence["k8s_db_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.databaseEncryption
}

source_path[{"k8s_db_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.databaseEncryption
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "databaseEncryption"]
        ],
    }
}

gc_issue["k8s_db_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.databaseEncryption.state) != "encrypted"
}

source_path[{"k8s_db_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.databaseEncryption.state) != "encrypted"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "databaseEncryption"]
        ],
    }
}

gc_issue["k8s_db_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.databaseEncryption.keyName
}

source_path[{"k8s_db_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.databaseEncryption.keyName
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "databaseEncryption", "keyName"]
        ],
    }
}

gc_issue["k8s_db_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.databaseEncryption.keyName) == 0
}

source_path[{"k8s_db_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.databaseEncryption.keyName) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "databaseEncryption", "keyName"]
        ],
    }
}

k8s_db_encrypt {
    lower(input.resources[i].type) == "container.v1.cluster"
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
    "Policy Code": "PR-GCP-GDF-CLT-022",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes cluster Application-layer Secrets not encrypted",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etcd._x005F_x000D_ _x005F_x000D_ This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-023
#

default k8s_intra_node = null

gc_issue["k8s_intra_node"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.networkConfig.enableIntraNodeVisibility
}

source_path[{"k8s_intra_node": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.networkConfig.enableIntraNodeVisibility
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "networkConfig", "enableIntraNodeVisibility"]
        ],
    }
}

k8s_intra_node {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_intra_node"]
}

k8s_intra_node = false {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_err = "GCP Kubernetes cluster intra-node visibility disabled" {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-023",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes cluster intra-node visibility disabled",
    "Policy Description": "With Intranode Visibility, all network traffic in your cluster is seen by the Google Cloud Platform network. This means you can see flow logs for all traffic between Pods, including traffic between Pods on the same node. And you can create firewall rules that apply to all traffic between Pods._x005F_x000D_ _x005F_x000D_ This policy checks your cluster's intra-node visibility feature and generates an alert if it's disabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-024
#

default k8s_istio = null

gc_issue["k8s_istio"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.addonsConfig.istioConfig.disabled == false
}

source_path[{"k8s_istio": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.addonsConfig.istioConfig.disabled == false
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "addonsConfig", "istioConfig", "disabled"]
        ],
    }
}

k8s_istio {
    lower(input.resources[i].type) == "container.v1.cluster"
    not gc_issue["k8s_istio"]
}

k8s_istio = false {
    gc_issue["k8s_istio"]
}

k8s_istio_err = "GCP Kubernetes cluster istioConfig not enabled" {
    gc_issue["k8s_istio"]
}

k8s_istio_metadata := {
    "Policy Code": "PR-GCP-GDF-CLT-024",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes cluster istioConfig not enabled",
    "Policy Description": "Istio is an open service mesh that provides a uniform way to connect, manage, and secure microservices. It supports managing traffic flows between services, enforcing access policies, and aggregating telemetry data, all without requiring changes to the microservice code._x005F_x000D_ _x005F_x000D_ This policy checks your cluster for the Istio add-on feature and alerts if it is not enabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-025
#

default k8s_zones = null

gc_issue["k8s_zones"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.zone
    count(resource.properties.locations) < 3
}

source_path[{"k8s_zones": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.zone
    count(resource.properties.locations) < 3
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "locations"]
        ],
    }
}

k8s_zones {
    lower(input.resources[i].type) == "container.v1.cluster"
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
    "Policy Code": "PR-GCP-GDF-CLT-025",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes cluster not in redundant zones",
    "Policy Description": "Putting resources in different zones in a region provides isolation from many types of infrastructure, hardware, and software failures._x005F_x000D_ _x005F_x000D_ This policy alerts if your cluster is not located in at least 3 zones.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}

#
# PR-GCP-GDF-CLT-026
#

default k8s_auto_upgrade = null

gc_attribute_absence["k8s_auto_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.currentNodeCount
}

source_path[{"k8s_auto_upgrade": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.currentNodeCount
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "currentNodeCount"]
        ],
    }
}

gc_issue["k8s_auto_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    to_number(resource.properties.currentNodeCount) < 3
    resource.properties.nodePools[j].management.autoUpgrade
}

source_path[{"k8s_auto_upgrade": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    to_number(resource.properties.currentNodeCount) < 3
    resource.properties.nodePools[j].management.autoUpgrade
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "nodePools", j, "management", "autoUpgrade"]
        ],
    }
}

gc_issue["k8s_auto_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.databaseEncryption.keyName
}

source_path[{"k8s_auto_upgrade": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.databaseEncryption.keyName
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "databaseEncryption", "keyName"]
        ],
    }
}

gc_issue["k8s_auto_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.databaseEncryption.keyName) == 0
}

source_path[{"k8s_auto_upgrade": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.databaseEncryption.keyName) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "databaseEncryption", "keyName"]
        ],
    }
}

k8s_auto_upgrade {
    lower(input.resources[i].type) == "container.v1.cluster"
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
    "Policy Code": "PR-GCP-GDF-CLT-026",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Kubernetes cluster size contains less than 3 nodes with auto upgrade enabled",
    "Policy Description": "Ensure your Kubernetes cluster size contains 3 or more nodes. (Clusters smaller than 3 may experience downtime during upgrades.)_x005F_x000D_ _x005F_x000D_ This policy checks the size of your cluster pools and alerts if there are fewer than 3 nodes in a pool.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}
