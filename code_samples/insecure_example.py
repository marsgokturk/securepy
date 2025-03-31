import json
import mysql.connector

def lambda_handler(event, context):
    connection = mysql.connector.connect(
        host='localhost',
        user='admin',
        password='admin123',
        database='mydatabase'
    )

    public_ip = event["queryStringParameters"]["publicIP"]

    cursor = connection.cursor()
    sql = f"UPDATE EC2ServerPublicIP SET publicIP = '{public_ip}' WHERE ID = 1"
    cursor.execute(sql)
    connection.commit()

    return {
        'statusCode': 200,
        'body': json.dumps({'publicIP': public_ip})
    }