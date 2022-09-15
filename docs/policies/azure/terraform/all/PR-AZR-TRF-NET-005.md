



# Master Test ID: PR-AZR-TRF-NET-005


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vnetsubnets.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NET-005|
|eval|data.rule.vnet_subnet_nsg|
|message|data.rule.vnet_subnet_nsg_err|
|remediationDescription|In 'azurerm_subnet_network_security_group_association' resource, make sure both 'subnet_id' and 'network_security_group_id' property exist and both has id from 'azurerm_subnet' and 'azurerm_network_security_group' resource respectively to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet_network_security_group_association#network_security_group_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_NET_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure Virtual Network subnet should be configured with Network Security Group

***<font color="white">Description:</font>*** This policy identifies Azure Virtual Network (VNet) subnets that are not associated with a Network Security Group (NSG). While binding an NSG to a network interface of a Virtual Machine (VM) enables fine-grained control to the VM, associating a NSG to a subnet enables better control over network traffic to all resources within a subnet. As a best practice, associate an NSG with a subnet so that you can protect your VMs on a subnet-level.<br><br>For more information, see https://blogs.msdn.microsoft.com/igorpag/2016/05/14/azure-network-security-groups-nsg-best-practices-and-lessons-learned/  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v.4.0.1-A&A-03', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-07', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-HRS-04', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-13', 'CSA CCM v.4.0.1-STA-14', 'CSA CCM v.4.0.1-TVM-01', 'CSA CCM v.4.0.1-TVM-07', 'CSA CCM v.4.0.1-TVM-08', 'CSA CCM v.4.0.1-TVM-09', 'CSA CCM v.4.0.1-TVM-10', 'CSA CCM v.4.0.1-UEM-03', 'CSA CCM v.4.0.1-UEM-05', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.001', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.002', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.n', 'HITRUST v.9.4.2-Control Reference:01.o', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.6.1', 'ISO/IEC 27002:2013-12.6.2', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-14.2.4', 'ISO/IEC 27002:2013-14.2.5', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27002:2013-16.1.2', 'ISO/IEC 27002:2013-16.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-18.2.1', 'ISO/IEC 27002:2013-5.1.1', 'ISO/IEC 27002:2013-6.2.2', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-16.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'ISO/IEC 27018:2019-18.2.1', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection \| Separate Subnets for Connecting to Different Security Domains', 'NIST 800-53 Rev4-SC-7 (22)', 'NIST CSF', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.CM-6', 'NIST CSF-DE.CM-7', 'NIST CSF-DE.DP-2', 'NIST CSF-ID.RA-1', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.6', 'NIST SP 800-171 Revision 2-3.14.6', 'NIST SP 800-172-3.14.3e', 'PCI DSS', 'PCI DSS v3.2.1-1.2.1', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_subnet']


[vnetsubnets.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vnetsubnets.rego
