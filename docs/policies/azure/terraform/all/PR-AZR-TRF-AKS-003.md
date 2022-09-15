



# Master Test ID: PR-AZR-TRF-AKS-003


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-003|
|eval|data.rule.aks_monitoring|
|message|data.rule.aks_monitoring_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, set enabled = true under 'oms_agent' which exist under 'addon_profile' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure AKS cluster monitoring should be enabled

***<font color="white">Description:</font>*** Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 41", "CyberSecurity Law of the People's Republic of China-Article 43", "CyberSecurity Law of the People's Republic of China-Article 44", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Continuous Monitoring', 'NIST 800-53 Rev4-CA-7e', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3', 'PIPEDA', 'PIPEDA-4.1.4']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
