package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters

#
# PR-AZR-AKS-001
#

default aks_cni_net = null

azure_attribute_absence["aks_cni_net"] {
    not input.properties.networkProfile.networkPlugin
}

azure_issue["aks_cni_net"] {
    lower(input.properties.networkProfile.networkPlugin) != "azure"
}

aks_cni_net {
    not azure_issue["aks_cni_net"]
    not azure_attribute_absence["aks_cni_net"]
}

aks_cni_net = false {
    azure_issue["aks_cni_net"]
}

aks_cni_net = false {
    azure_attribute_absence["aks_cni_net"]
}

aks_cni_net_err = "Azure AKS cluster Azure CNI networking not enabled" {
    azure_issue["aks_cni_net"]
} else = "AKS cluster attribute networkProfile.networkPlugin missing in the resource" {
    azure_attribute_absence["aks_cni_net"]
}

aks_cni_net_metadata := {
    "Policy Code": "PR-AZR-AKS-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure AKS cluster Azure CNI networking not enabled",
    "Policy Description": "Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}

#
# PR-AZR-AKS-002
#

default aks_http_routing = null

azure_attribute_absence["aks_http_routing"] {
    not input.properties.addonProfiles.httpApplicationRouting.enabled
}

azure_issue["aks_http_routing"] {
    input.properties.addonProfiles.httpApplicationRouting.enabled == true
}

aks_http_routing {
    not azure_attribute_absence["aks_http_routing"]
    not azure_issue["aks_http_routing"]
}

aks_http_routing = false {
    azure_issue["aks_http_routing"]
}

aks_http_routing {
    azure_attribute_absence["aks_http_routing"]
}

aks_http_routing_err = "Azure AKS cluster HTTP application routing is currently enabled. Please disable it." {
    azure_issue["aks_http_routing"]
} else = "AKS cluster attribute addonProfiles.httpApplicationRouting is missing from the resource. Which is fine." {
    azure_attribute_absence["aks_http_routing"]
}

aks_http_routing_metadata := {
    "Policy Code": "PR-AZR-AKS-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure AKS cluster HTTP application routing should be disabled",
    "Policy Description": "HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}

#
# PR-AZR-AKS-003
#

default aks_monitoring = null

azure_attribute_absence["aks_monitoring"] {
    not input.properties.addonProfiles.omsagent.enabled
}

azure_issue["aks_monitoring"] {
    input.properties.addonProfiles.omsagent.enabled != true
}

aks_monitoring {
    not azure_issue["aks_monitoring"]
    not azure_attribute_absence["aks_monitoring"]
}

aks_monitoring = false {
    azure_issue["aks_monitoring"]
}

aks_monitoring = false {
    azure_attribute_absence["aks_monitoring"]
}

aks_monitoring_err = "Azure AKS cluster monitoring not enabled" {
    azure_issue["aks_monitoring"]
} else = "AKS cluster attribute addonProfiles.omsagent missing in the resource" {
    azure_attribute_absence["aks_monitoring"]
}

aks_monitoring_metadata := {
    "Policy Code": "PR-AZR-AKS-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure AKS cluster monitoring not enabled",
    "Policy Description": "Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}

#
# PR-AZR-AKS-004
#

default aks_nodes = null

azure_attribute_absence["aks_nodes"] {
    not input.properties.agentPoolProfiles
}

azure_issue["aks_nodes"] {
    agentPoolProfiles := input.properties.agentPoolProfiles[_]
    min([ c | c := agentPoolProfiles.count]) < 3
}

aks_nodes {
    not azure_issue["aks_nodes"]
    not azure_attribute_absence["aks_nodes"]
}

aks_nodes = false {
    azure_issue["aks_nodes"]
}

aks_nodes = false {
    azure_attribute_absence["aks_nodes"]
}

aks_nodes_err = "Azure AKS cluster pool profile count contains less than 3 nodes" {
    azure_issue["aks_nodes"]
} else = "AKS cluster attribute agentPoolProfiles missing in the resource" {
    azure_attribute_absence["aks_nodes"]
}

aks_nodes_metadata := {
    "Policy Code": "PR-AZR-AKS-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure AKS cluster pool profile count contains less than 3 nodes",
    "Policy Description": "Ensure your AKS cluster pool profile count contains 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}

#
# PR-AZR-AKS-005
#

default aks_rbac = null

azure_attribute_absence["aks_rbac"] {
    not input.properties.enableRBAC
}

azure_issue["aks_rbac"] {
    input.properties.enableRBAC != true
}

aks_rbac {
    not azure_issue["aks_rbac"]
    not azure_attribute_absence["aks_rbac"]
}

aks_rbac = false {
    azure_issue["aks_rbac"]
}

aks_rbac = false {
    azure_attribute_absence["aks_rbac"]
}

aks_rbac_err = "Azure AKS enable role-based access control (RBAC) not enforced" {
    azure_issue["aks_rbac"]
} else = "AKS cluster attribute enableRBAC missing in the resource" {
    azure_attribute_absence["aks_rbac"]
}

aks_rbac_metadata := {
    "Policy Code": "PR-AZR-AKS-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure AKS enable role-based access control (RBAC) not enforced",
    "Policy Description": "To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}

#
# PR-AZR-AKS-006
#

default aks_aad_azure_rbac = null

azure_issue["aks_aad_azure_rbac"] {
    not input.properties.aadProfile.managed
}

azure_issue["aks_aad_azure_rbac"] {
    not input.properties.aadProfile.enableAzureRBAC
}

azure_issue["aks_aad_azure_rbac"] {
    input.properties.aadProfile.managed != true
}

azure_issue["aks_aad_azure_rbac"] {
    input.properties.aadProfile.enableAzureRBAC != true
}

aks_aad_azure_rbac {
    not azure_issue["aks_aad_azure_rbac"]
}

aks_aad_azure_rbac = false {
    azure_issue["aks_aad_azure_rbac"]
}

aks_aad_azure_rbac_err = "Managed Azure AD RBAC for AKS cluster is not enabled." {
    azure_issue["aks_aad_azure_rbac"]
}

aks_aad_azure_rbac_metadata := {
    "Policy Code": "PR-AZR-AKS-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Managed Azure AD RBAC for AKS cluster should be enabled",
    "Policy Description": "Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}


#
# PR-AZR-AKS-007
#

default aks_authorized_Ip = null

azure_attribute_absence["aks_authorized_Ip"] {
    not input.properties.apiServerAccessProfile.authorizedIPRanges
}

azure_issue["aks_authorized_Ip"] {
    count(input.properties.apiServerAccessProfile.authorizedIPRanges) == 0
}

aks_authorized_Ip {
    not azure_attribute_absence["aks_authorized_Ip"]
    not azure_issue["aks_authorized_Ip"]
}

aks_authorized_Ip = false {
    azure_issue["aks_authorized_Ip"]
}

aks_authorized_Ip = false {
    azure_attribute_absence["aks_authorized_Ip"]
}

aks_authorized_Ip_err = "AKS API server does not define authorized IP ranges" {
    azure_issue["aks_authorized_Ip"]
} else = "microsoft.containerservice/managedclusters resource property apiServerAccessProfile.authorizedIPRanges missing in the resource" {
    azure_attribute_absence["aks_authorized_Ip"]
}


aks_authorized_Ip_metadata := {
    "Policy Code": "PR-AZR-AKS-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure AKS API server defines authorized IP ranges",
    "Policy Description": "The AKS API server receives requests to perform actions in the cluster , for example, to create resources, and scale the number of nodes. The API server provides a secure way to manage a cluster.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}



#
# PR-AZR-AKS-008
#

default network_policy = null

azure_attribute_absence["network_policy"] {
    not input.properties.networkProfile.networkPolicy
}


azure_issue["network_policy"] {
    lower(input.properties.networkProfile.networkPolicy) != "azure"
}

network_policy {
    not azure_attribute_absence["network_policy"]
    not azure_issue["network_policy"]
}

network_policy = false {
    azure_issue["network_policy"]
}

network_policy = false {
    azure_attribute_absence["network_policy"]
}

network_policy_err = "AKS cluster network policies are not enforced" {
    azure_issue["network_policy"]
} else = "microsoft.containerservice/managedclusters resource property networkProfile.networkPolicy missing in the resource" {
    azure_attribute_absence["network_policy"]
}


network_policy_metadata := {
    "Policy Code": "PR-AZR-AKS-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure AKS cluster network policies are enforced",
    "Policy Description": "Network policy options in AKS include two ways to implement a network policy. You can choose between Azure Network Policies or Calico Network Policies. In both cases, the underlying controlling layer is based on Linux IPTables to enforce the specified policies. Policies are translated into sets of allowed and disallowed IP pairs. These pairs are then programmed as IPTable rules.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}


# https://www.danielstechblog.io/disable-the-kubernetes-dashboard-on-azure-kubernetes-service/
# PR-AZR-AKS-009
#

default aks_kub_dashboard_disabled = null

azure_attribute_absence["aks_kub_dashboard_disabled"] {
    not input.properties.addonProfiles.kubeDashboard.enabled
}

azure_issue["aks_kub_dashboard_disabled"] {
    input.properties.addonProfiles.kubeDashboard.enabled != false
}

aks_kub_dashboard_disabled {
    azure_attribute_absence["aks_kub_dashboard_disabled"]
    not azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled {
    not azure_attribute_absence["aks_kub_dashboard_disabled"]
    not azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled = false {
    azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled_err = "Kubernetes Dashboard is currently not disabled" {
    azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled_metadata := {
    "Policy Code": "PR-AZR-AKS-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Kubernetes Dashboard is disabled",
    "Policy Description": "Disable the Kubernetes dashboard on Azure Kubernetes Service",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}
