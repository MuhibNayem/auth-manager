# AWS Security Best Practices Guide for Tessera Package

## 🚨 CRITICAL: Never Hardcode Credentials

**NEVER** pass AWS access keys or secret keys directly in your code, configuration files, or version control.

```python
# ❌ WRONG - SECURITY RISK
db = DynamoDBAdapter({
    'region': 'us-east-1',
    'access_key': 'AKIAIOSFODNN7EXAMPLE',  # NEVER DO THIS
    'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'  # NEVER DO THIS
})

# ✅ CORRECT - Use IAM Roles
db = DynamoDBAdapter({
    'region': 'us-east-1',
    'table_prefix': 'prod_tessera_'
})
# Credentials automatically resolved from IAM Role
```

---

## 🔐 AWS Credential Provider Chain

The Tessera Package follows the standard AWS SDK credential resolution order:

### Priority Order (Highest to Lowest)

1. **Explicit Configuration** (Not Recommended - triggers security warnings)
2. **Environment Variables** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
3. **Shared Credentials File** (`~/.aws/credentials`)
4. **Config File** (`~/.aws/config`)
5. **Assume Role Provider** (via AWS_PROFILE or role_arn config)
6. **IAM Role for EC2** (Instance Metadata Service)
7. **IAM Role for ECS** (Task Role)
8. **IAM Role for Lambda** (Execution Role)
9. **IAM Role for EKS** (IRSA - IAM Roles for Service Accounts)

---

## 🏢 Production Deployment Scenarios

### 1. EC2 Instances

**Recommended:** Attach an IAM Role to your EC2 instance.

**Steps:**
1. Create IAM Role with DynamoDB permissions
2. Attach role to EC2 instance
3. No credentials needed in code!

```bash
# Create IAM Policy
aws iam create-policy \
  --policy-name TesseraDynamoDBPolicy \
  --policy-document file://tessera-policy.json

# Create IAM Role for EC2
aws iam create-role \
  --role-name TesseraEC2Role \
  --assume-role-policy-document file://ec2-trust.json

# Attach policy to role
aws iam attach-role-policy \
  --role-name TesseraEC2Role \
  --policy-arn arn:aws:iam::123456789012:policy/TesseraDynamoDBPolicy

# Launch instance with role
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --iam-instance-profile Name=TesseraEC2Profile
```

**Python Code:**
```python
# No credentials needed - automatically uses instance role
db = DynamoDBAdapter({
    'region': 'us-east-1',
    'table_prefix': 'prod_tessera_'
})
await db.connect()
```

---

### 2. ECS (Elastic Container Service)

**Recommended:** Use ECS Task Roles.

**Task Definition Example:**
```json
{
  "family": "tessera-service",
  "containerDefinitions": [
    {
      "name": "tessera-container",
      "image": "your-registry/tessera:latest"
    }
  ],
  "taskRoleArn": "arn:aws:iam::123456789012:role/TesseraECSTaskRole",
  "executionRoleArn": "arn:aws:iam::123456789012:role/TesseraECSExecutionRole"
}
```

**Python Code:**
```python
# Automatically uses task role
db = DynamoDBAdapter({
    'region': 'us-west-2',
    'table_prefix': 'prod_tessera_'
})
```

---

### 3. AWS Lambda

**Recommended:** Use Lambda Execution Role.

**Configuration:**
1. Create IAM Role with DynamoDB permissions
2. Set as Lambda execution role
3. No environment variables needed!

```python
# Lambda handler
async def lambda_handler(event, context):
    db = DynamoDBAdapter({'region': 'us-east-1'})
    await db.connect()
    # Use db...
```

---

### 4. EKS (Kubernetes) - IRSA

**Recommended:** IAM Roles for Service Accounts (IRSA).

**Steps:**

1. **Create IAM Role with Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED123456"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED123456:sub": "system:serviceaccount:tessera:tessera-sa"
        }
      }
    }
  ]
}
```

2. **Create Kubernetes Service Account:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tessera-sa
  namespace: tessera
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/TesseraEKSRole
```

3. **Deploy Application:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tessera-deployment
spec:
  template:
    spec:
      serviceAccountName: tessera-sa
      containers:
      - name: tessera
        image: your-registry/tessera:latest
        env:
        - name: AWS_REGION
          value: "us-west-2"
```

---

## 💻 Local Development

### Option 1: AWS SSO (Recommended for Enterprises)

```bash
# Configure SSO
aws configure sso

# Login
aws sso login

# Your session is automatically refreshed
```

### Option 2: Shared Credentials File

```bash
# Create ~/.aws/credentials
[default]
region = us-east-1
output = json

[profile tessera-dev]
region = us-east-1
```

**Never commit this file to version control!**

### Option 3: Environment Variables (Temporary)

```bash
# For local testing only
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1

# Run your application
python app.py
```

⚠️ **Warning:** Environment variables can leak through logs and process listings. Use only for short-lived local development.

### Option 4: AWS Secrets Manager (Advanced)

For enhanced security, retrieve credentials at runtime:

```python
import boto3
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "tessera/aws/credentials"
    region_name = "us-east-1"
    
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except ClientError as e:
        raise e
```

---

## 🔗 Cross-Account Access

For accessing DynamoDB in another AWS account:

### Method 1: Role Assumption via AWS_PROFILE

**~/.aws/config:**
```ini
[profile tessera-prod]
role_arn = arn:aws:iam::987654321098:role/TesseraCrossAccountRole
source_profile = default
external_id = your-external-id-here
```

**Python:**
```python
import os
os.environ['AWS_PROFILE'] = 'tessera-prod'

db = DynamoDBAdapter({'region': 'us-east-1'})
```

### Method 2: Programmatic Role Assumption

```python
import boto3

def assume_role(role_arn, external_id=None):
    sts = boto3.client('sts')
    
    kwargs = {
        'RoleArn': role_arn,
        'RoleSessionName': 'TesseraSession'
    }
    
    if external_id:
        kwargs['ExternalId'] = external_id
    
    credentials = sts.assume_role(**kwargs)['Credentials']
    return credentials

# Use temporary credentials
creds = assume_role('arn:aws:iam::987654321098:role/TesseraRole')

db = DynamoDBAdapter({
    'region': 'us-east-1',
    'access_key': creds['AccessKeyId'],
    'secret_key': creds['SecretAccessKey'],
    # Note: These are temporary and will expire
})
```

---

## 🛡️ IAM Policy Examples

### Minimum Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:123456789012:table/tessera_*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:ListTables"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/tessera_*"
    }
  ]
}
```

### Enhanced Security (Production)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TesseraDynamoDBAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:TransactGetItems",
        "dynamodb:TransactWriteItems"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:123456789012:table/prod_tessera_users",
        "arn:aws:dynamodb:us-east-1:123456789012:table/prod_tessera_sessions",
        "arn:aws:dynamodb:us-east-1:123456789012:table/prod_tessera_organizations",
        "arn:aws:dynamodb:us-east-1:123456789012:index/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "AllowCloudWatchMetrics",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "cloudwatch:namespace": "Tessera"
        }
      }
    }
  ]
}
```

---

## 🔍 Security Checklist

- [ ] **NO** hardcoded credentials in source code
- [ ] **NO** credentials in `.env` files committed to git
- [ ] **USE** IAM Roles for all production workloads
- [ ] **ENABLE** CloudTrail logging for DynamoDB API calls
- [ ] **IMPLEMENT** least-privilege IAM policies
- [ ] **ROTATE** credentials regularly (if using static credentials)
- [ ] **ENABLE** encryption at rest for DynamoDB tables
- [ ] **ENABLE** encryption in transit (TLS)
- [ ] **USE** VPC endpoints for DynamoDB (private connectivity)
- [ ] **MONITOR** unusual access patterns with CloudWatch

---

## 📚 Additional Resources

- [AWS Security Best Practices](https://docs.aws.amazon.com/securitybestpractices/latest/userguide/credentials.html)
- [Boto3 Credentials Guide](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html)
- [IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [ECS Task IAM Roles](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
- [Lambda Execution Roles](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)

---

## 🆘 Troubleshooting

### Error: "AWS credentials not found"

**Solutions:**
1. Verify IAM Role is attached to your compute resource
2. Check trust relationship for cross-account roles
3. Ensure `AWS_REGION` environment variable is set
4. For local dev: Run `aws configure sso` or check `~/.aws/credentials`

### Error: "Access Denied" / "User is not authorized"

**Solutions:**
1. Review IAM policy permissions
2. Check resource ARNs in policy match your table names
3. Verify no explicit DENY statements in policies
4. Check SCPs (Service Control Policies) at organization level

### Error: "Token has expired"

**Solutions:**
1. For temporary credentials: Implement automatic refresh
2. Check system clock synchronization
3. Verify role session duration settings

---

## ⚠️ Security Incident Response

If you accidentally expose credentials:

1. **IMMEDIATELY** rotate the compromised credentials
2. **REVOKE** active sessions using those credentials
3. **REVIEW** CloudTrail logs for unauthorized access
4. **NOTIFY** your security team
5. **UPDATE** secrets management procedures

```bash
# Rotate access key
aws iam update-access-key --access-key-id AKIA... --status Inactive
aws iam delete-access-key --access-key-id AKIA...

# Create new key
aws iam create-access-key
```

---

**Remember:** Security is everyone's responsibility. Always follow the principle of least privilege and never commit credentials to version control.
