# Authentication with AWS EKS clusters

This document covers the case of retrieving Kubernetes credentials for an AWS EKS cluster from Google Cloud GKE or Azure AKS environments.

## Source authentication

### Prerequisites for GKE source authentication

For this application running on a Google Cloud GKE cluster/GCE VM:

1. A Google Cloud environment configured with IAM identity. This could be a VM instance using a service account identity or a GKE pod configured with GKE workload identity. Workload identity can be easily configured using the official workload identity [terraform module](https://registry.terraform.io/modules/terraform-google-modules/kubernetes-engine/google/latest/submodules/workload-identity).
2. An AWS role that is configured to trust the GCP service account used in the environment running the program. This involves setting up AWS IAM role trust policy for `sts:AssumeRoleWithWebIdentity` action specifying `accounts.google.com` federated principal (more documentation [here](https://gist.github.com/wvanderdeijl/c6a9a9f26149cea86039b3608e3556c1)).
3. The IAM role from step 2. having appropriate permissions (policies attached) for EKS cluster(s) management.

### Prerequisites for AKS source authentication

For this application running on a Azure AKS cluster:

1. An Azure Entra object (such as) user assigned managed identity with workload identity set up for the Kubernetes service account this application' pod is set up to use.
2. An OIDC provider configured in AWS IAM for the source Microsoft Entra tennant.
3. AWS role that is configured to trust the Azure managed identity from step 1. and OIDC provider from step 2. Example:

    ```json
    "Statement": [ {
        "Sid": "AllowAzureServiceAccount",
        "Effect": "Allow",
        "Principal": {
            "Federated": "arn:aws:iam::012345678910:oidc-provider/sts.windows.net/12345678-1234-1234-1234-123456789abc/"
        },
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {
                "sts.windows.net/12345678-1234-1234-1234-123456789abc/:aud": "12345678-1234-1234-1234-123456789abc"
            }
        }
    }]
    ```

4. The IAM role from step 3. having appropriate permissions (policies attached) for EKS cluster(s) management.

## Usage

* **--rolearn**: The AWS IAM role ARN to assume (required).
* **--cluster**: The name of the AWS EKS cluster for which you need credentials (required).
* **--stsregion**: AWS STS region to which requests are made (optional, default: us-east-1).

Example:

```bash
k8xauth eks --rolearn "arn:aws:iam::123456789012:role/argocdrole" --cluster "my-eks-cluster-name" --stsregion "us-east-1"
```
