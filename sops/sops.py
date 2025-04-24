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
