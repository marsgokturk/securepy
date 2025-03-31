import json
import mysql.connector
from mysql.connector import Error
import os

def get_database_connection():
    try:
        db_config = {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME')
        }
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def lambda_handler(event, context):
    connection = get_database_connection()
    if connection is None:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Database connection failed'})
        }

    public_ip = event.get("queryStringParameters", {}).get("publicIP")
    if not public_ip:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing publicIP parameter'})
        }

    try:
        cursor = connection.cursor(prepared=True)
        sql = "UPDATE EC2ServerPublicIP SET publicIP = %s WHERE ID = %s"
        cursor.execute(sql, (public_ip, 1))
        connection.commit()
        return {
            'statusCode': 200,
            'body': json.dumps({'publicIP': public_ip})
        }
    except Error as e:
        print(f"Error executing query: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Database operation failed'})
        }
    finally:
        cursor.close()
        connection.close()