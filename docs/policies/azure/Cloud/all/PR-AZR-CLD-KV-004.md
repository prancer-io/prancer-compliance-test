



# Title: Azure Key Vault keys should have an expiration date


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-004

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyvaultKey.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-004|
|eval|data.rule.kv_keys_expire|
|message|data.rule.kv_keys_expire_err|
|remediationDescription|1. Go to 'Key vaults' and choose your Key Vault<br>2. Select 'Keys' under 'Settings' in the navigation menu<br>3. Select the relevant key and reselect its current version<br>4. Check 'Set expiration date'<br>4. Save.<br>Please visit <a href='https://docs.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_KV_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v3)-GS-3', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-8.1', 'CIS v1.2.0 (Azure)-8.1', 'CIS v1.3.0 (Azure)-8.1', 'CIS v1.3.1 (Azure)-8.1', 'CIS v1.4.0 (Azure)-8.1', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 24", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.187', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1098', 'MITRE ATT&CK v6.3-T1098', 'MITRE ATT&CK v8.2-T1078', 'MITRE ATT&CK v8.2-T1098', 'NIST 800', 'NIST 800-53 Rev 5-Cryptographic Key Establishment and Management', 'NIST 800-53 Rev4-SC-12', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.10', 'NIST SP 800-172-3.5.2e', 'PCI DSS', 'PCI DSS v3.2.1-4.1', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['Security']|



[KeyvaultKey.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/KeyvaultKey.rego
