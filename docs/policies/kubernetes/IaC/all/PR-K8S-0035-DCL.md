



# Title:  Ensure that Service Account Tokens are only mounted where necessary (RBAC)


***<font color="white">Master Test Id:</font>*** TEST_SERVICE_ACCOUNT

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([serviceAccount.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0035-DCL|
|eval|data.rule.sa_token|
|message|data.rule.sa_token_err|
|remediationDescription|Modify the definition of pods and service accounts which do not need to mount service account tokens to disable it.|
|remediationFunction|PR-K8S-0035-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>***  Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server. Mounting service account tokens inside pods can provide an avenue for privilege escalation attacks where an attacker is able to compromise a single pod in the cluster. Avoiding mounting these tokens removes this attack avenue.   
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['serviceaccount']


[serviceAccount.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/serviceAccount.rego
