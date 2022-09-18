



# Prancer Compliance test

## Introduction

### Prancer is a pre-deployment and post-deployment multi-cloud security platform for your Infrastructure as Code (IaC) and live cloud environment. It shifts the security to the left and provides end-to-end security scanning based on the Policy as Code concept. DevOps engineers can use it for static code analysis on IaC to find security drifts and maintain their cloud security posture with continuous compliance features.


----------------------------------------------------


#### These are list of policies related to post deployment tests. These tests contribute to have continuous compliance in the cloud


----------------------------------------------------


***<font color="white">Master Test ID:</font>*** K8S_test_0001

***<font color="white">ID:</font>*** PR-K8S-0001

***Title: [MINIMIZE ACCESS TO SECRETS (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0002

***<font color="white">ID:</font>*** PR-K8S-0002

***Title: [Minimize wildcard use in Roles and ClusterRoles (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0003

***<font color="white">ID:</font>*** PR-K8S-0003

***Title: [Ensure that default service accounts are not actively used. (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0004

***<font color="white">ID:</font>*** PR-K8S-0004

***Title: [Ensure that the cluster-admin role is only used where required (RBAC)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0008

***<font color="white">ID:</font>*** PR-K8S-0008

***Title: [Minimize the admission of privileged containers (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0009

***<font color="white">ID:</font>*** PR-K8S-0009

***Title: [Minimize the admission of root containers (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0010

***<font color="white">ID:</font>*** PR-K8S-0010

***Title: [Minimize the admission of containers with the NET_RAW capability (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0011

***<font color="white">ID:</font>*** PR-K8S-0011

***Title: [Minimize the admission of containers wishing to share the host IPC namespace (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0012

***<font color="white">ID:</font>*** PR-K8S-0012

***Title: [Minimize the admission of containers wishing to share the host network namespace (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0013

***<font color="white">ID:</font>*** PR-K8S-0013

***Title: [Minimize the admission of containers wishing to share the host process ID namespace (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0014

***<font color="white">ID:</font>*** PR-K8S-0014

***Title: [Minimize the admission of containers with allowPrivilegeEscalation (PSP)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0015

***<font color="white">ID:</font>*** PR-K8S-0015

***Title: [Do not admit root containers]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0016

***<font color="white">ID:</font>*** PR-K8S-0016

***Title: [Ensure that the --peer-client-cert-auth argument is set to true (etcd)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0017

***<font color="white">ID:</font>*** PR-K8S-0017

***Title: [Ensure that the --peer-auto-tls argument is not set to true (etcd)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0018

***<font color="white">ID:</font>*** PR-K8S-0018

***Title: [Ensure that Containers are not running in privileged mode]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0019

***<font color="white">ID:</font>*** PR-K8S-0019

***Title: [ Ensure that the admission control plugin AlwaysAdmit is not set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0020

***<font color="white">ID:</font>*** PR-K8S-0020

***Title: [ Ensure that the --basic-auth-file argument is not set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0021

***<font color="white">ID:</font>*** PR-K8S-0021

***Title: [Ensure that the seccomp profile is set to runtime/default in your pod definitions]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0022

***<font color="white">ID:</font>*** PR-K8S-0022

***Title: [ Ensure that the --profiling argument is set to false (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0023

***<font color="white">ID:</font>*** PR-K8S-0023

***Title: [Ensure containers are secured with AppArmor profile]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0024

***<font color="white">ID:</font>*** PR-K8S-0024

***Title: [ Ensure that the --kubelet-certificate-authority argument is set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0025

***<font color="white">ID:</font>*** PR-K8S-0025

***Title: [ Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0026

***<font color="white">ID:</font>*** PR-K8S-0026

***Title: [Ensure that the admission control plugin PodSecurityPolicy is set (API Server)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0027

***<font color="white">ID:</font>*** PR-K8S-0027

***Title: [ Ensure that the --authorization-mode argument includes RBAC (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0028

***<font color="white">ID:</font>*** PR-K8S-0028

***Title: [ Ensure that the --anonymous-auth argument is set to false (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0029

***<font color="white">ID:</font>*** PR-K8S-0029

***Title: [ Ensure that the --profiling argument is set to false (Scheduler) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0030

***<font color="white">ID:</font>*** PR-K8S-0030

***Title: [ The default namespace should not be used ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0031

***<font color="white">ID:</font>*** PR-K8S-0031

***Title: [ Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0032

***<font color="white">ID:</font>*** PR-K8S-0032

***Title: [ Ensure that the --profiling argument is set to false (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0033

***<font color="white">ID:</font>*** PR-K8S-0033

***Title: [ Ensure that the --use-service-account-credentials argument is set to true (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0034

***<font color="white">ID:</font>*** PR-K8S-0034

***Title: [ Ensure that the --root-ca-file argument is set as appropriate (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0035

***<font color="white">ID:</font>*** PR-K8S-0035

***Title: [ Ensure that Service Account Tokens are only mounted where necessary (RBAC) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0036

***<font color="white">ID:</font>*** PR-K8S-0036

***Title: [ Restrict Traffic Among Pods with a Network Policy]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0041

***<font color="white">ID:</font>*** PR-K8S-0041

***Title: [ Ensure that the admission control plugin EventRateLimit is set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0042

***<font color="white">ID:</font>*** PR-K8S-0042

***Title: [ Ensure that the --insecure-bind-address argument is not set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0043

***<font color="white">ID:</font>*** PR-K8S-0043

***Title: [ Ensure that the --secure-port argument is not set to 0 (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0044

***<font color="white">ID:</font>*** PR-K8S-0044

***Title: [ Ensure that the --repair-malformed-updates argument is set to false (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0045

***<font color="white">ID:</font>*** PR-K8S-0045

***Title: [ Ensure that the admission control plugin AlwaysPullImages is set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0046

***<font color="white">ID:</font>*** PR-K8S-0046

***Title: [ Ensure that the admission control plugin NamespaceLifecycle is set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0047

***<font color="white">ID:</font>*** PR-K8S-0047

***Title: [ Ensure that the --insecure-allow-any-token argument is not set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0048

***<font color="white">ID:</font>*** PR-K8S-0048

***Title: [ Ensure that the --authorization-mode argument is set to Node (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0049

***<font color="white">ID:</font>*** PR-K8S-0049

***Title: [ Ensure that the admission control plugin NodeRestriction is set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0050

***<font color="white">ID:</font>*** PR-K8S-0050

***Title: [ Ensure that the --insecure-port argument is set to 0 (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0052

***<font color="white">ID:</font>*** PR-K8S-0052

***Title: [ Ensure that the --address argument is set to 127.0.0.1 (Scheduler) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0053

***<font color="white">ID:</font>*** PR-K8S-0053

***Title: [ Ensure that the --address argument is set to 127.0.0.1 (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0054

***<font color="white">ID:</font>*** PR-K8S-0054

***Title: [ Ensure that the admission control plugin DenyEscalatingExec is set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0055

***<font color="white">ID:</font>*** PR-K8S-0055

***Title: [ Ensure that the --bind-address argument is set to 127.0.0.1 (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0056

***<font color="white">ID:</font>*** PR-K8S-0056

***Title: [ Ensure that the --bind-address argument is set to 127.0.0.1 (Scheduler) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0057

***<font color="white">ID:</font>*** PR-K8S-0057

***Title: [ Ensure pods outside of kube-system do not have access to node volume ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0058

***<font color="white">ID:</font>*** PR-K8S-0058

***Title: [ Ensure that the --authorization-mode argument is not set to AlwaysAllow (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0059

***<font color="white">ID:</font>*** PR-K8S-0059

***Title: [ Ensure that the --audit-log-path argument is set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0060

***<font color="white">ID:</font>*** PR-K8S-0060

***Title: [ Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0061

***<font color="white">ID:</font>*** PR-K8S-0061

***Title: [ Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0062

***<font color="white">ID:</font>*** PR-K8S-0062

***Title: [ Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0063

***<font color="white">ID:</font>*** PR-K8S-0063

***Title: [ Ensure that the AdvancedAuditing argument is not set to false (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0067

***<font color="white">ID:</font>*** PR-K8S-0067

***Title: [ Ensure that the RotateKubeletServerCertificate argument is set to true (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0068

***<font color="white">ID:</font>*** PR-K8S-0068

***Title: [ Ensure that the --etcd-cafile argument is set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0069

***<font color="white">ID:</font>*** PR-K8S-0069

***Title: [ Ensure that the --kubelet-https argument is set to true (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0070

***<font color="white">ID:</font>*** PR-K8S-0070

***Title: [ Ensure that the --service-account-private-key-file argument is set as appropriate (Controller Manager) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0071

***<font color="white">ID:</font>*** PR-K8S-0071

***Title: [ Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0072

***<font color="white">ID:</font>*** PR-K8S-0072

***Title: [ Ensure that the --client-cert-auth argument is set to true (etcd) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0073

***<font color="white">ID:</font>*** PR-K8S-0073

***Title: [ Ensure that the --auto-tls argument is not set to true (etcd) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0074

***<font color="white">ID:</font>*** PR-K8S-0074

***Title: [ Ensure that the --token-auth-file parameter is not set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0075

***<font color="white">ID:</font>*** PR-K8S-0075

***Title: [ Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0076

***<font color="white">ID:</font>*** PR-K8S-0076

***Title: [ Ensure that the --client-ca-file argument is set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0078

***<font color="white">ID:</font>*** PR-K8S-0078

***Title: [ Ensure that the --service-account-lookup argument is set to true (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0079

***<font color="white">ID:</font>*** PR-K8S-0079

***Title: [ Ensure that the admission control plugin ServiceAccount is set (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0083

***<font color="white">ID:</font>*** PR-K8S-0083

***Title: [ Ensure that the --service-account-key-file argument is set as appropriate (API Server) ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** K8S_test_0084

***<font color="white">ID:</font>*** PR-K8S-0084

***Title: [ Apply Security Context to Your Pods and Containers ]***

----------------------------------------------------


[ Apply Security Context to Your Pods and Containers ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0084.md
[ Ensure pods outside of kube-system do not have access to node volume ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0057.md
[ Ensure that Service Account Tokens are only mounted where necessary (RBAC) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0035.md
[ Ensure that the --address argument is set to 127.0.0.1 (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0053.md
[ Ensure that the --address argument is set to 127.0.0.1 (Scheduler) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0052.md
[ Ensure that the --anonymous-auth argument is set to false (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0028.md
[ Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0060.md
[ Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0061.md
[ Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0062.md
[ Ensure that the --audit-log-path argument is set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0059.md
[ Ensure that the --authorization-mode argument includes RBAC (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0027.md
[ Ensure that the --authorization-mode argument is not set to AlwaysAllow (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0058.md
[ Ensure that the --authorization-mode argument is set to Node (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0048.md
[ Ensure that the --auto-tls argument is not set to true (etcd) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0073.md
[ Ensure that the --basic-auth-file argument is not set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0020.md
[ Ensure that the --bind-address argument is set to 127.0.0.1 (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0055.md
[ Ensure that the --bind-address argument is set to 127.0.0.1 (Scheduler) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0056.md
[ Ensure that the --client-ca-file argument is set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0076.md
[ Ensure that the --client-cert-auth argument is set to true (etcd) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0072.md
[ Ensure that the --etcd-cafile argument is set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0068.md
[ Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0071.md
[ Ensure that the --insecure-allow-any-token argument is not set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0047.md
[ Ensure that the --insecure-bind-address argument is not set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0042.md
[ Ensure that the --insecure-port argument is set to 0 (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0050.md
[ Ensure that the --kubelet-certificate-authority argument is set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0024.md
[ Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0025.md
[ Ensure that the --kubelet-https argument is set to true (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0069.md
[ Ensure that the --profiling argument is set to false (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0022.md
[ Ensure that the --profiling argument is set to false (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0032.md
[ Ensure that the --profiling argument is set to false (Scheduler) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0029.md
[ Ensure that the --repair-malformed-updates argument is set to false (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0044.md
[ Ensure that the --root-ca-file argument is set as appropriate (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0034.md
[ Ensure that the --secure-port argument is not set to 0 (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0043.md
[ Ensure that the --service-account-key-file argument is set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0083.md
[ Ensure that the --service-account-lookup argument is set to true (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0078.md
[ Ensure that the --service-account-private-key-file argument is set as appropriate (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0070.md
[ Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0031.md
[ Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0075.md
[ Ensure that the --token-auth-file parameter is not set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0074.md
[ Ensure that the --use-service-account-credentials argument is set to true (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0033.md
[ Ensure that the AdvancedAuditing argument is not set to false (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0063.md
[ Ensure that the RotateKubeletServerCertificate argument is set to true (Controller Manager) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0067.md
[ Ensure that the admission control plugin AlwaysAdmit is not set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0019.md
[ Ensure that the admission control plugin AlwaysPullImages is set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0045.md
[ Ensure that the admission control plugin DenyEscalatingExec is set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0054.md
[ Ensure that the admission control plugin EventRateLimit is set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0041.md
[ Ensure that the admission control plugin NamespaceLifecycle is set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0046.md
[ Ensure that the admission control plugin NodeRestriction is set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0049.md
[ Ensure that the admission control plugin ServiceAccount is set (API Server) ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0079.md
[ Restrict Traffic Among Pods with a Network Policy]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0036.md
[ The default namespace should not be used ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0030.md
[Do not admit root containers]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0015.md
[Ensure containers are secured with AppArmor profile]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0023.md
[Ensure that Containers are not running in privileged mode]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0018.md
[Ensure that default service accounts are not actively used. (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0003.md
[Ensure that the --peer-auto-tls argument is not set to true (etcd)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0017.md
[Ensure that the --peer-client-cert-auth argument is set to true (etcd)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0016.md
[Ensure that the admission control plugin PodSecurityPolicy is set (API Server)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0026.md
[Ensure that the cluster-admin role is only used where required (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0004.md
[Ensure that the seccomp profile is set to runtime/default in your pod definitions]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0021.md
[MINIMIZE ACCESS TO SECRETS (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0001.md
[Minimize the admission of containers wishing to share the host IPC namespace (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0011.md
[Minimize the admission of containers wishing to share the host network namespace (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0012.md
[Minimize the admission of containers wishing to share the host process ID namespace (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0013.md
[Minimize the admission of containers with allowPrivilegeEscalation (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0014.md
[Minimize the admission of containers with the NET_RAW capability (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0010.md
[Minimize the admission of privileged containers (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0008.md
[Minimize the admission of root containers (PSP)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0009.md
[Minimize wildcard use in Roles and ClusterRoles (RBAC)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/kubernetes/Cloud/all/PR-K8S-0002.md
