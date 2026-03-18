
import json
import boto3
import time
import uuid

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('NetSentinel_Data')

def lambda_handler(event, context):
    try:
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event

        network_name = body.get('network_id', 'Unknown_Network')
        devices_dict = body.get('devices', {})
        dns_logs = body.get('dns_logs', []) 

        now = int(time.time())

        # 1. Update Devices
        for mac, device_info in devices_dict.items():
            if isinstance(device_info, dict):
                ip = device_info.get('ip', '0.0.0.0')
                name = device_info.get('name', 'Unknown-Device')
            else:
                ip = str(device_info)
                name = 'Unknown-Device'

            table.update_item(
                Key={'mac_address': mac},
                UpdateExpression="SET device_name = if_not_exists(device_name, :inc_name), ip_address = :ip, network_id = :net, #st = if_not_exists(#st, :def_status), last_seen = :time",
                ExpressionAttributeNames={'#st': 'status'},
                ExpressionAttributeValues={
                    ':inc_name': name, ':ip': ip, ':net': network_name,
                    ':def_status': 'PENDING', ':time': now
                }
            )
            
        # 2. Save On-Demand DNS Logs 
        if dns_logs:
            expire_time = now + 2592000 
            with table.batch_writer() as batch:
                for log in dns_logs:
                    batch.put_item(
                        Item={
                            'mac_address': 'DNS_LOG',         
                            'ip_address': f"{log.get('query')}-{str(uuid.uuid4())[:8]}",   
                            'source_ip': log.get('source_ip'),
                            'query': log.get('query'),
                            'timestamp': log.get('timestamp', now),
                            'expire_at': expire_time          
                        }
                    )

        # 3. THE C2 DISPATCHER: Read Commands for the Agent
        response = table.scan()
        blacklist = []
        hearing_list = []
        for item in response.get('Items', []):
            if item.get('network_id') == network_name:
                if item.get('status') == 'BLOCKED':
                    blacklist.append(item.get('mac_address'))
                if item.get('dns_monitor') == True:
                    hearing_list.append(item.get('mac_address'))

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Success', 
                'blacklist': blacklist,
                'hearing_list': hearing_list
            })
        }
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps(f'Server Error: {str(e)}')}
