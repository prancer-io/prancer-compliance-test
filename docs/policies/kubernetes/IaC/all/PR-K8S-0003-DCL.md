



# Title: Ensure that default service accounts are not actively used. (RBAC)


***<font color="white">Master Test Id:</font>*** TEST_ROLE_BINDING_1

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([roleBinding.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0003-DCL|
|eval|data.rule.default_role|
|message|data.rule.default_role_err|
|remediationDescription|Create explicit service accounts wherever a Kubernetes workload requires specific access to the Kubernetes API server. Modify the configuration of each default service account to include this value: automountServiceAccountToken: false|
|remediationFunction|PR-K8S-0003-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The default service account should not be used to ensure that rights granted to applications can be more easily audited and reviewed. Kubernetes provides a default service account which is used by cluster workloads where no specific service account is assigned to the pod. Where access to the Kubernetes API from a pod is required, a specific service account should be created for that pod, and rights granted to that service account. The default service account should be configured such that it does not provide a service account token and does not have any explicit rights assignments.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['rolebinding', 'clusterrolebinding']


[roleBinding.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/roleBinding.rego
