



# Master Test ID: PR-AZR-TRF-AKS-001


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-001|
|eval|data.rule.aks_cni_net|
|message|data.rule.aks_cni_net_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, set network_plugin = 'azure' under 'network_profile' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#network_policy' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure AKS cluster CNI networking should be enabled

***<font color="white">Description:</font>*** Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.2.179', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection \| Connections to Public Networks', 'NIST 800-53 Rev4-CA-3 (4)', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
