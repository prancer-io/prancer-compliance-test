



# Master Test ID: PR-AZR-TRF-STR-012


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageblobcontainers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-012|
|eval|data.rule.storage_container_public_access_disabled|
|message|data.rule.storage_container_public_access_disabled_err|
|remediationDescription|In 'azurerm_storage_container' resource, set 'container_access_type = private' or remove the container_access_type property to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container#container_access_type' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_012.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Azure storage blob container should not have public access enabled

***<font color="white">Description:</font>*** 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-GS-2', 'Azure Security Benchmark (v2)-NS-1', 'Azure Security Benchmark (v3)-AM-4', 'Azure Security Benchmark (v3)-IM-7', 'Azure Security Benchmark (v3)-PA-7', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-3.6', 'CIS v1.2.0 (Azure)-3.5', 'CIS v1.3.0 (Azure)-3.5', 'CIS v1.3.1 (Azure)-3.5', 'CIS v1.4.0 (Azure)-3.5', "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", 'CMMC', "CyberSecurity Law of the People's Republic of China-Article 45", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection', 'NIST 800-53 Rev4-SC-7', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PIPEDA', 'PIPEDA-4.1.4']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_container']


[storageblobcontainers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego
