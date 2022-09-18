



# Title: Ensure Azure App Service Authentication is enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-WEB-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([appservice.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-WEB-005|
|eval|data.rule.app_service_auth_enabled|
|message|data.rule.app_service_auth_enabled_err|
|remediationDescription|In 'azurerm_app_service' resource, set 'enabled = true' under 'auth_settings' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_WEB_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure app service which dont have authentication enabled and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark (v2)-GS-6', 'Azure Security Benchmark (v2)-PA-5', 'Azure Security Benchmark (v3)-AM-4', 'Azure Security Benchmark (v3)-IM-7', 'Azure Security Benchmark (v3)-PA-7', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-9.1', 'CIS v1.2.0 (Azure)-9.1', 'CIS v1.3.0 (Azure)-9.1', 'CIS v1.3.1 (Azure)-9.1', 'CIS v1.4.0 (Azure)-9.1', 'CSA', 'CSA CCM v.4.0.1-HRS-06', 'CSA CCM v.4.0.1-IAM-01', 'CSA CCM v.4.0.1-IAM-03', 'CSA CCM v.4.0.1-IAM-06', 'CSA CCM v.4.0.1-IAM-07', 'CSA CCM v.4.0.1-IAM-08', 'CSA CCM v.4.0.1-IAM-10', 'CSA CCM v.4.0.1-IAM-16', 'CSA CCM v.4.0.1-IVS-03', "CyberSecurity Law of the People's Republic of China-Article 21", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-IA.1.077', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-5.1.2', 'ISO/IEC 27002:2013-8.1.1', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27002:2013-9.4.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27017:2015-9.4.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'NIST 800', 'NIST 800-53 Rev 5-Service Identification and Authentication', 'NIST 800-53 Rev4-IA-9', 'NIST CSF', 'NIST CSF-PR.AC-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.5.2', 'NIST SP 800-172-3.5.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_app_service']


[appservice.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
