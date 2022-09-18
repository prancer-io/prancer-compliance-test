



# Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-002

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-002|
|eval|data.rule.enableSoftDelete|
|message|data.rule.enableSoftDelete_err|
|remediationDescription|Via Azure Portal<br>Azure Portal does not have provision to update the respective configurations<br><br>Via Azure CLI<br>Existing key vault:<br><br>For an existing key vault named ContosoVault, enable soft-delete as follows:<br><br>az resource update --ids $(az keyvault show --name ContosoVault -o tsv , awk '{print $1}') --set properties.enableSoftDelete=true.<br>Please visit <a href='https://docs.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_KV_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates), etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-BR-3', 'Azure Security Benchmark (v3)-GS-8', 'Brazilian Data Protection Law (LGPD)-Article 42', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-8.4', 'CIS v1.2.0 (Azure)-8.4', 'CIS v1.3.0 (Azure)-8.4', 'CIS v1.3.1 (Azure)-8.4', 'CIS v1.4.0 (Azure)-8.6', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AM.4.226', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.c', 'HITRUST v.9.4.2-Control Reference:06.d', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction', 'NIST 800', 'NIST 800-53 Rev 5-Cryptographic Key Establishment and Management', 'NIST 800-53 Rev4-SC-12', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.10', 'NIST SP 800-172-3.1.1e', 'PCI DSS', 'PCI DSS v3.2.1-3.1', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
