



# Master Test ID: PR-AZR-TRF-AKS-004


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-004|
|eval|data.rule.aks_nodes|
|message|data.rule.aks_nodes_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, set node_count = 3 under 'default_node_pool' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#node_count' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Azure AKS cluster pool profile should have minimum 3 or more nodes

***<font color="white">Description:</font>*** Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AM.4.226', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
