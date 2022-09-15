



# Master Test ID: PR-AZR-TRF-STR-010


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-010|
|eval|data.rule.storage_account_public_access_disabled|
|message|data.rule.storage_account_public_access_disabled_err|
|remediationDescription|In 'azurerm_storage_account' resource, set 'allow_blob_public_access = false' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#allow_blob_public_access' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure that Storage Account should not allow public access to all blobs or containers

***<font color="white">Description:</font>*** This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-NS-1', 'Azure Security Benchmark (v3)-AM-4', 'Azure Security Benchmark (v3)-GS-7', 'Azure Security Benchmark (v3)-IM-7', 'Azure Security Benchmark (v3)-PA-7', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CIS', 'CIS v1.1 (Azure)-5.1.5', 'CIS v1.3.0 (Azure)-5.1.3', 'CIS v1.3.1 (Azure)-5.1.3', 'CIS v1.4.0 (Azure)-5.1.3', "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 45", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.049', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'NIST 800', 'NIST 800-53 Rev 5-Protection of Audit Information', 'NIST 800-53 Rev4-AU-9', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
