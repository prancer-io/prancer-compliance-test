# Prancer Compliance test repository

## Introduction
Prancer is a pre-deployment and post-deployment multi-cloud security platform for your Infrastructure as Code (IaC) and live cloud environment. It shifts the security to the left and provides end-to-end security scanning based on the Policy as Code concept. DevOps engineers can use it for static code analysis on IaC to find security drifts and maintain their cloud security posture with continuous compliance features. you can get more information from our website at : https://www.prancer.io

## How to use the repository
The easiest way to get up and running is to make sure you can run the scenario we are explaining in the [Hello World example](https://www.prancer.io/guidance/). after being able to run that simple scenario, you can use this repository to do more advance tests.

The repository consists of 4 high level folders:
 - AWS
 - Azure
 - Google
 - Kubernetes

Under each top level directory, we have `cloud`, `iac` and `terraform` folders which hold the `rego` files respectively.

## Prerequisites
Make sure you have the following prerequisites available:
 - Linux distribution
 - Python 3.6.8 / 3.8 / 3.9
 - Prancer Basic [How to install prancer basic](https://docs.prancer.io/installation/)
 - OPA [How to install OPA binary](https://www.openpolicyagent.org/docs/latest/#running-opa)
 > Note: We recommend moving `opa` to a directory included in your system's `PATH` (i.e `/usr/local/bin/`)

 ## Sample scenario
 There are lots of usecases avaialble for the [Prancer Platform](https://www.prancer.io/introduction/?section=use-case-scenarios). Here I will show you a sample scenario to IaC Scan Azure ARM template.

 > The complete code is available in the [Hello World](https://github.com/prancer-io/prancer-hello-world) repository

### step 1 - create a connector file to your IaC code repo
You should create a connector file to your IaC repository (https://github.com/prancer-io/prancer-hello-world/blob/master/gitConnectorArm.json)

```
    {
    "fileType": "structure",
    "type": "filesystem",
    "companyName": "prancer",
    "gitProvider": "https://github.com/prancer-io/prancer-armof.git",
    "branchName": "master",
    "private": false
    }
```

### step 2 - 