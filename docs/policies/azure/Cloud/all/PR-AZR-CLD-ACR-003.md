



# Title: Azure Container Registry should not use the deprecated classic registry


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ACR-003

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_224']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([registry.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ACR-003|
|eval|data.rule.acr_classic|
|message|data.rule.acr_classic_err|
|remediationDescription|Using Azure CLI:<br>az acr update --name --sku {Basic, Premium, Standard}<br><br>References : <a href='https://docs.microsoft.com/en-us/azure/container-registry/container-registry-skus' target='_blank'>https://docs.microsoft.com/en-us/azure/container-registry/container-registry-skus</a>|
|remediationFunction|PR_AZR_CLD_ACR_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry.<br><br>For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 46', 'Brazilian Data Protection Law (LGPD)-Article 6', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-IA.2.078', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2, ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1525 - Implant Internal Image', 'MITRE ATT&CK v6.3-T1525', 'MITRE ATT&CK v8.2-T1525', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3']|
|service|['Containers']|



[registry.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/registry.rego
