



# Title: Ensure that Storage Account should not allow public access to all blobs or containers


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-010

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-010|
|eval|data.rule.blobServicePublicAccessDisabled|
|message|data.rule.blobServicePublicAccessDisabled_err|
|remediationDescription|To disallow public access for a storage account in the Azure portal, follow these steps:<br><br>1. Navigate to your storage account in the Azure portal.<br>2. Locate the Configuration setting under Settings.<br>3. Set Blob public access to Disabled.|
|remediationFunction|PR_AZR_CLD_STR_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify which Storage Account has public access enabled for all blobs or containers  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-NS-1', 'Azure Security Benchmark (v3)-AM-4', 'Azure Security Benchmark (v3)-GS-7', 'Azure Security Benchmark (v3)-IM-7', 'Azure Security Benchmark (v3)-PA-7', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CIS', 'CIS v1.1 (Azure)-5.1.5', 'CIS v1.3.0 (Azure)-5.1.3', 'CIS v1.3.1 (Azure)-5.1.3', 'CIS v1.4.0 (Azure)-5.1.3', "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 45", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.049', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'NIST 800', 'NIST 800-53 Rev 5-Protection of Audit Information', 'NIST 800-53 Rev4-AU-9', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
