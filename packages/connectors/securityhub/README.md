# @blockioc/connector-securityhub

AWS Security Hub connector for BlockIOC forensics events.

## Overview

This connector forwards decrypted BlockIOC forensics events to AWS Security Hub as findings in the AWS Security Finding Format (ASFF).

## Installation

```bash
npm install @blockioc/connector-securityhub @blockioc/connector-sdk
```

## Usage

```typescript
import { SecurityHubConnector } from '@blockioc/connector-securityhub';

const connector = new SecurityHubConnector({
  type: 'securityhub',
  name: 'prod-securityhub',
  enabled: true,
  region: 'us-east-1',
  awsAccountId: '123456789012',
  severityLabel: 'HIGH',
});

await connector.init();

// Send a forensics event
const result = await connector.send({
  eventId: 'evt-123',
  blockedUrl: 'https://malicious.com/phish',
  timestamp: new Date().toISOString(),
  redirectChain: ['https://example.com', 'https://malicious.com/phish'],
  tabContext: {
    tabId: 1,
    windowId: 1,
    incognito: false,
  },
  orgId: 'org-123',
  matchType: 'domain',
  matchedIndicator: 'malicious.com',
  raw: {},
});

if (result.success) {
  console.log('Finding created:', result.response?.findingId);
}

await connector.close();
```

## Configuration

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `type` | `'securityhub'` | Yes | - | Connector type |
| `name` | `string` | Yes | - | Instance name |
| `enabled` | `boolean` | Yes | - | Whether connector is enabled |
| `region` | `string` | Yes | - | AWS region (e.g., 'us-east-1') |
| `awsAccountId` | `string` | Yes | - | AWS account ID |
| `credentials` | `AwsCredentials` | No | Default chain | AWS credentials |
| `productArn` | `string` | No | Auto-generated | Custom product ARN |
| `severityLabel` | `string` | No | `'HIGH'` | Finding severity |
| `findingTypePrefix` | `string` | No | `'Software and Configuration Checks/BlockIOC'` | Custom type prefix |

## AWS Credentials

The connector supports multiple authentication methods:

### Default Credential Chain (Recommended)

Uses environment variables, IAM role, or AWS config file automatically:

```typescript
{
  // No credentials config - uses default chain
}
```

### Explicit Access Keys

```typescript
{
  credentials: {
    type: 'access-key',
    accessKeyId: 'EXAMPLEACCESSKEY12345',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  }
}
```

### AWS Profile

```typescript
{
  credentials: {
    type: 'profile',
    profile: 'my-profile',
  }
}
```

## IAM Permissions

The connector requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:BatchImportFindings",
        "securityhub:DescribeHub"
      ],
      "Resource": "*"
    }
  ]
}
```

## Finding Format

Events are transformed to ASFF findings with:

- **Schema Version**: `2018-10-08`
- **Finding Type**: Based on match type (MaliciousDomain, MaliciousURL, MaliciousHash)
- **Severity**: Configurable (default: HIGH)
- **Resources**: Blocked URL with context
- **Product Fields**: BlockIOC metadata (org ID, match type, etc.)

## License

MIT
