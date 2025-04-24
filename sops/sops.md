我将帮你创建一个AWS Lambda函数，用于从AWS Secrets Manager读取并解密使用SOPS和KMS密钥加密的秘密。以下是一个使用Python的Lambda函数实现，包含必要的权限配置建议。

```python
import json
import boto3
import base64
import yaml
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    # 初始化 Secrets Manager 和 KMS 客户端
    secrets_client = boto3.client('secretsmanager')
    kms_client = boto3.client('kms')
    
    # 替换为你的 Secrets Manager 秘密名称
    secret_name = "your-secret-name"
    
    try:
        # 从 Secrets Manager 获取加密的秘密
        get_secret_value_response = secrets_client.get_secret_value(
            SecretId=secret_name
        )
        
        # 获取加密的秘密值
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            
        # 解析 SOPS 加密的 YAML/JSON 格式秘密
        secret_dict = yaml.safe_load(secret)
        
        # 检查是否是 SOPS 加密的数据
        if 'sops' in secret_dict and 'kms' in secret_dict['sops']:
            # 获取加密的数据
            encrypted_data = secret_dict.get('encrypted_data')
            
            # 使用 KMS 解密
            try:
                # 假设 SOPS 使用了 KMS 加密，提取密文
                # 注意：实际的密文位置可能需要根据你的 SOPS 配置调整
                ciphertext = base64.b64decode(secret_dict['sops']['kms'][0]['enc'])
                
                # 使用 KMS 解密
                decrypted_response = kms_client.decrypt(
                    CiphertextBlob=ciphertext,
                    EncryptionContext={'LambdaFunctionName': context.function_name}
                )
                
                # 获取解密后的明文
                decrypted_secret = decrypted_response['Plaintext'].decode('utf-8')
                
                # 解析解密后的秘密（假设是 JSON/YAML 格式）
                decrypted_secret_dict = yaml.safe_load(decrypted_secret)
                
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': 'Secret retrieved and decrypted successfully',
                        'secret': decrypted_secret_dict
                    })
                }
                
            except ClientError as e:
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': f"KMS decryption error: {str(e)}"
                    })
                }
                
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Secret is not SOPS-encrypted or invalid format'
                })
            }
            
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f"Secrets Manager error: {str(e)}"
            })
        }
```

### 说明和配置建议：

1. **依赖安装**：
   - 确保在 Lambda 部署包或层中包含以下 Python 库：
     - `boto3`（AWS SDK，已包含在 Lambda 运行时）
     - `pyyaml`（用于解析 YAML 格式的秘密）
   - 你可以通过以下命令创建部署包：
     ```bash
     pip install pyyaml -t ./package
     cd package
     zip -r ../lambda_function.zip .
     cd ..
     zip -g lambda_function.zip lambda_function.py
     ```

2. **IAM 权限**：
   - 为 Lambda 函数附加以下权限（通过 IAM 角色）：
     ```json
     {
         "Version": "2012-10-17",
         "Statement": [
             {
                 "Effect": "Allow",
                 "Action": [
                     "secretsmanager:GetSecretValue",
                     "secretsmanager:DescribeSecret"
                 ],
                 "Resource": "arn:aws:secretsmanager:<region>:<account-id>:secret:your-secret-name-*"
             },
             {
                 "Effect": "Allow",
                 "Action": [
                     "kms:Decrypt"
                 ],
                 "Resource": "arn:aws:kms:<region>:<account-id>:key/<your-kms-key-id>"
             },
             {
                 "Effect": "Allow",
                 "Action": [
                     "logs:CreateLogGroup",
                     "logs:CreateLogStream",
                     "logs:PutLogEvents"
                 ],
                 "Resource": "*"
             }
         ]
     }
     ```

3. **环境变量**：
   - 将 `secret_name` 替换为你的 Secrets Manager 中的实际秘密名称。
   - 如果需要，可以通过 Lambda 环境变量配置 `secret_name`：
     ```python
     secret_name = os.environ.get('SECRET_NAME', 'your-secret-name')
     ```

4. **SOPS 配置注意事项**：
   - 代码假设你的秘密是以 YAML 格式存储，并使用 KMS 加密。如果使用 JSON 或其他格式，请相应调整 `yaml.safe_load` 的解析逻辑。
   - SOPS 加密的秘密结构可能因配置不同而异。你可能需要根据你的 SOPS 配置调整代码中访问密文（`secret_dict['sops']['kms'][0]['enc']`）的逻辑。
   - 如果你的 SOPS 配置使用了多个 KMS 密钥，需遍历 `secret_dict['sops']['kms']` 列表。

5. **错误处理**：
   - 代码包含基本的错误处理，捕获 Secrets Manager 和 KMS 的客户端错误。
   - 你可以根据需要添加更详细的错误处理或日志记录。

6. **测试**：
   - 在 Lambda 控制台中，创建一个测试事件（可以是空的 JSON `{}`），运行函数以验证是否能正确读取和解密秘密。
   - 确保 KMS 密钥策略允许 Lambda 角色的 `kms:Decrypt` 操作。

7. **安全建议**：
   - 确保 Secrets Manager 和 KMS 密钥的访问权限严格受限，仅允许必要的角色访问。
   - 使用 AWS CloudTrail 监控 Secrets Manager 和 KMS 的访问日志。

如果你的 SOPS 配置有特殊要求（例如特定的加密上下文或不同的密文结构），请提供更多细节，我可以帮你进一步调整代码！
