



# Master Test ID: PR-AZR-TRF-WEB-015


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(appservice.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-WEB-015|
|eval: |data.rule.app_service_python_version_latest|
|message: |data.rule.app_service_python_version_latest_err|
|remediationDescription: |In 'azurerm_app_service' resource, set python_version = '3.9' under 'site_config' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_WEB_015.py|


severity: Medium

title: Azure App Service Pyhton version should be latest

description: This policy will identify the Azure app service which dont have latest version of Pyhton and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-PV-3', 'Azure Security Benchmark (v2)-PV-7', 'Azure Security Benchmark (v3)-AM-2', 'Azure Security Benchmark (v3)-AM-5', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-9.9', 'CIS v1.2.0 (Azure)-9.9', 'CIS v1.3.0 (Azure)-9.8', 'CIS v1.3.1 (Azure)-9.8', 'CIS v1.4.0 (Azure)-9.8', "CyberSecurity Law of the People's Republic of China-Article 25", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-RM.4.148', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1190 - Exploit Public-Facing Application', 'MITRE ATT&CK v6.3-T1190', 'MITRE ATT&CK v8.2-T1190', 'NIST 800', 'NIST 800-53 Rev 5-Flaw Remediation \| Removal of Previous Versions of Software and Firmware', 'NIST 800-53 Rev4-SI-2 (6)', 'NIST CSF', 'NIST CSF-DE.CM-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.9', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3', 'PIPEDA', 'PIPEDA-4.7.3']|
|service: |['terraform']|


resourceTypes: ['azurerm_app_service']


[file(appservice.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
