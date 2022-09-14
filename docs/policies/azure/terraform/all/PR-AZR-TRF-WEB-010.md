



# Master Test ID: PR-AZR-TRF-WEB-010


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(appservice.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-WEB-010|
|eval: |data.rule.app_service_managed_identity_provider_enabled|
|message: |data.rule.app_service_managed_identity_provider_enabled_err|
|remediationDescription: |In 'azurerm_app_service' resource, make sure property 'type' exist under 'identity' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#identity' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_WEB_010.py|


severity: Medium

title: Azure App Service Managed Identity provider should be enabled

description: This policy will identify the Azure app service which dont have Managed Identity provider enabled and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-IM-1', 'Azure Security Benchmark (v3)-GS-6', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-9.5', 'CIS v1.2.0 (Azure)-9.5', 'CIS v1.3.0 (Azure)-9.5', 'CIS v1.3.1 (Azure)-9.5', 'CIS v1.4.0 (Azure)-9.5', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-HRS-04', 'CSA CCM v.4.0.1-IAM-01', 'CSA CCM v.4.0.1-IAM-04', 'CSA CCM v.4.0.1-IAM-05', 'CSA CCM v.4.0.1-IAM-09', 'CSA CCM v.4.0.1-IAM-14', 'CSA CCM v.4.0.1-IAM-16', 'CSA CCM v.4.0.1-UEM-13', "CyberSecurity Law of the People's Republic of China-Article 21", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AM.4.226', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-5.1.2', 'ISO/IEC 27002:2013-6.1.2', 'ISO/IEC 27002:2013-6.2.1', 'ISO/IEC 27002:2013-6.2.2', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.1.2', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.4', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27002:2013-9.4.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-9.1.2', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.4', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27017:2015-9.4.2', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'ISO/IEC 27018:2019-9.4.2', 'NIST CSF', 'NIST CSF-PR.AC-3', 'NIST CSF-PR.AC-4', 'NIST CSF-PR.PT-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.1', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3', 'PIPEDA', 'PIPEDA-4.7.3']|
|service: |['terraform']|


resourceTypes: ['azurerm_app_service']


[file(appservice.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
