



# Title: Azure AKS enable role-based access control (RBAC) should be enforced


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AKS-005

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AKS-005|
|eval|data.rule.aks_rbac|
|message|data.rule.aks_rbac_err|
|remediationDescription|Make sure you are following the ARM template guidelines for AKS by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters' target='_blank'>here</a>. Set enable RBAC to true to enable Kubernetes Role-Based Access Control.|
|remediationFunction|PR_AZR_ARM_AKS_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster._x005F<br>_x005F<br>This policy checks your AKS cluster RBAC setting and alerts if disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-14', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark (v2)-PA-7', 'Azure Security Benchmark (v3)-PA-1', 'Azure Security Benchmark (v3)-PA-7', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-8.5', 'CIS v1.2.0 (Azure)-8.5', 'CIS v1.3.0 (Azure)-8.5', 'CIS v1.3.1 (Azure)-8.5', 'CIS v1.4.0 (Azure)-8.7', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IAM-04', 'CSA CCM v.4.0.1-IAM-05', 'CSA CCM v.4.0.1-IAM-09', 'CSA CCM v.4.0.1-IAM-16', "CyberSecurity Law of the People's Republic of China-Article 21", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-6.1.2', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.1.2', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v8.2-T1078', 'NIST 800', 'NIST 800-53 Rev 5-Access Enforcement \| Role-based Access Control', 'NIST 800-53 Rev4-AC-3 (7)', 'NIST CSF', 'NIST CSF-PR.AC-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.1.2e', 'PCI DSS', 'PCI DSS v3.2.1-7.1', 'PCI DSS v3.2.1-7.1.2', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.containerservice/managedclusters']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/aks.rego
