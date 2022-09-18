



# Title: MINIMIZE ACCESS TO SECRETS (RBAC)


***<font color="white">Master Test Id:</font>*** TEST_ROLE_1

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([role.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0001-DCL|
|eval|data.rule.rbac_secrets|
|message|data.rule.rbac_secrets_err|
|remediationDescription|Where possible, remove get, list and watch access to secret objects in the cluster.|
|remediationFunction|PR-K8S-0001-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The Kubernetes API stores secrets, which may be service account tokens for the Kubernetes API or credentials used by workloads in the cluster. Access to these secrets should be restricted to the smallest possible group of users to reduce the risk of privilege escalation. Inappropriate access to secrets stored within the Kubernetes cluster can allow for an attacker to gain additional access to the Kubernetes cluster or external resources whose credentials are stored as secrets.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['role', 'clusterrole']


[role.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/role.rego
