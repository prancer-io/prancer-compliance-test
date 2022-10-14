



# Title: Minimize the admission of containers with the NET_RAW capability (PSP)


***<font color="white">Master Test Id:</font>*** TEST_POD_SECURITY_POLICY_3

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([podSecurityPolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0010-DCL|
|eval|data.rule.drop_capabilities|
|message|data.rule.drop_capabilities_err|
|remediationDescription|Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.requiredDropCapabilities is set to include either NET_RAW or ALL. References <a href='https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies' target='_blank'>here</a> and <a href='https://www.nccgroup.trust/uk/our-research/abusing-privileged-and-unprivileged-linux-containers/' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0010-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Do not generally permit containers with the potentially dangerous NET_RAW capability. Containers run with a default set of capabilities as assigned by the Container Runtime. By default this can include potentially dangerous capabilities. With Docker as the container runtime the NET_RAW capability is enabled which may be misused by malicious containers. Ideally, all containers should drop this capability. There should be at least one PodSecurityPolicy (PSP) defined which prevents containers with the NET_RAW capability from launching. If you need to run containers with this capability, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['podsecuritypolicy']


[podSecurityPolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/podSecurityPolicy.rego
