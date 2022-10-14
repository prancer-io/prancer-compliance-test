



# Title: Storage Accounts should have firewall rules enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-004

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-004|
|eval|data.rule.storage_acl|
|message|data.rule.storage_acl_err|
|remediationDescription|1. Go to Storage Accounts<br>2. For each storage account, Click on the settings menu called Firewalls and virtual networks.<br>3. Ensure that you have selected to allow access from Selected networks.<br>4. Add rules to allow traffic from specific network.<br>5. Click Save to apply your changes.<br>Azure Command Line Interface 2.0 Use the below command to update default-action to Deny.<br>Please visit <a href='https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_STR_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-GS-2', 'Azure Security Benchmark (v2)-NS-1', 'Azure Security Benchmark (v3)-GS-4', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-3.7', 'CIS v1.2.0 (Azure)-3.6', 'CIS v1.3.0 (Azure)-3.6', 'CIS v1.3.1 (Azure)-3.6', 'CIS v1.4.0 (Azure)-3.6', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', "CyberSecurity Law of the People's Republic of China-Article 21", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.d', 'HITRUST v.9.4.2-Control Reference:01.r', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection \| Block Communication from Non-organizationally Configured Hosts', 'NIST 800-53 Rev 5-Boundary Protection \| Deny by Default â\x80\x94 Allow by Exception', 'NIST 800-53 Rev 5-Boundary Protection \| Restrict Incoming Communications Traffic', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev 5-System Monitoring \| Inbound and Outbound Communications Traffic', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-7 (11)', 'NIST 800-53 Rev4-SC-7 (19)', 'NIST 800-53 Rev4-SC-7 (5)', 'NIST 800-53 Rev4-SI-4 (4)', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-2.1', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
