import requests, json, base64, sys
import pickle

def main_handler(event: dict, context: dict):
    data = event["body"]
    kwargs = json.loads(data)
    kwargs['data'] = base64.b64decode(kwargs['data'])
    try:
        req = requests.request(**kwargs, verify=False, allow_redirects=False)
        serializedReq = pickle.dumps(req)
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},#不要强制格式哦，会报错
            "body": base64.b64encode(serializedReq).decode("utf-8"),
        }
    except Exception as e:#可以以集群方式返回结果抛出异常
        exc_type, exc_value, exc_traceback = sys.exc_info()
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": str(exc_value).encode().decode("utf-8")#base64.b64encode(bytes(str(exc_value),'utf-8')).decode("utf-8"),
        }