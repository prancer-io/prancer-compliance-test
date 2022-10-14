



# Prancer Compliance test

## Introduction

### Prancer is a pre-deployment and post-deployment multi-cloud security platform for your Infrastructure as Code (IaC) and live cloud environment. It shifts the security to the left and provides end-to-end security scanning based on the Policy as Code concept. DevOps engineers can use it for static code analysis on IaC to find security drifts and maintain their cloud security posture with continuous compliance features.


----------------------------------------------------


#### These are list of policies related to ```IaC Security Scan``` for ```kubernetes```


----------------------------------------------------


***<font color="white">Master Test ID:</font>*** TEST_NETWORK_POLICY

***<font color="white">ID:</font>*** PR-K8S-0036-DCL

***Title: [Restrict Traffic Among Pods with a Network Policy]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_1

***<font color="white">ID:</font>*** PR-K8S-0015-DCL

***Title: [Do not admit root containers]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_2

***<font color="white">ID:</font>*** PR-K8S-0018-DCL

***Title: [Ensure that Containers are not running in privileged mode]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_3

***<font color="white">ID:</font>*** PR-K8S-0030-DCL

***Title: [The default namespace should not be used]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_4

***<font color="white">ID:</font>*** PR-K8S-0057-DCL

***Title: [ Ensure pods outside of kube-system do not have access to node volume]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_5

***<font color="white">ID:</font>*** PR-K8S-0084-DCL

***Title: [Apply Security Context to Your Pods and Containers]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_SECURITY_POLICY_1

***<font color="white">ID:</font>*** PR-K8S-0008-DCL

***Title: [Minimize the admission of privileged containers (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_SECURITY_POLICY_2

***<font color="white">ID:</font>*** PR-K8S-0009-DCL

***Title: [Minimize the admission of root containers (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_SECURITY_POLICY_3

***<font color="white">ID:</font>*** PR-K8S-0010-DCL

***Title: [Minimize the admission of containers with the NET_RAW capability (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_SECURITY_POLICY_4

***<font color="white">ID:</font>*** PR-K8S-0011-DCL

***Title: [Minimize the admission of containers wishing to share the host IPC namespace (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_SECURITY_POLICY_5

***<font color="white">ID:</font>*** PR-K8S-0012-DCL

***Title: [Minimize the admission of containers wishing to share the host network namespace (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_SECURITY_POLICY_6

***<font color="white">ID:</font>*** PR-K8S-0013-DCL

***Title: [Minimize the admission of containers wishing to share the host process ID namespace (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_POD_SECURITY_POLICY_7

***<font color="white">ID:</font>*** PR-K8S-0014-DCL

***Title: [Minimize the admission of containers with allowPrivilegeEscalation (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ROLE_1

***<font color="white">ID:</font>*** PR-K8S-0001-DCL

***Title: [MINIMIZE ACCESS TO SECRETS (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ROLE_2

***<font color="white">ID:</font>*** PR-K8S-0002-DCL

***Title: [Minimize wildcard use in Roles and ClusterRoles (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ROLE_BINDING_1

***<font color="white">ID:</font>*** PR-K8S-0003-DCL

***Title: [Ensure that default service accounts are not actively used. (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ROLE_BINDING_2

***<font color="white">ID:</font>*** PR-K8S-0004-DCL

***Title: [Ensure that the cluster-admin role is only used where required (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_SERVICE_ACCOUNT

***<font color="white">ID:</font>*** PR-K8S-0035-DCL

***Title: [ Ensure that Service Account Tokens are only mounted where necessary (RBAC)]***

----------------------------------------------------


[ Ensure pods outside of kube-system do not have access to node volume]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0057-DCL.md
[ Ensure that Service Account Tokens are only mounted where necessary (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0035-DCL.md
[Apply Security Context to Your Pods and Containers]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0084-DCL.md
[Do not admit root containers]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0015-DCL.md
[Ensure that Containers are not running in privileged mode]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0018-DCL.md
[Ensure that default service accounts are not actively used. (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0003-DCL.md
[Ensure that the cluster-admin role is only used where required (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0004-DCL.md
[MINIMIZE ACCESS TO SECRETS (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0001-DCL.md
[Minimize the admission of containers wishing to share the host IPC namespace (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0011-DCL.md
[Minimize the admission of containers wishing to share the host network namespace (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0012-DCL.md
[Minimize the admission of containers wishing to share the host process ID namespace (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0013-DCL.md
[Minimize the admission of containers with allowPrivilegeEscalation (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0014-DCL.md
[Minimize the admission of containers with the NET_RAW capability (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0010-DCL.md
[Minimize the admission of privileged containers (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0008-DCL.md
[Minimize the admission of root containers (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0009-DCL.md
[Minimize wildcard use in Roles and ClusterRoles (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0002-DCL.md
[Restrict Traffic Among Pods with a Network Policy]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0036-DCL.md
[The default namespace should not be used]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/IaC/all/PR-K8S-0030-DCL.md
