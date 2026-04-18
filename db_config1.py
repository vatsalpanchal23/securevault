import mysql.connector
from mysql.connector import Error

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="V@tsal128",
            database="password_manager",
            auth_plugin='mysql_native_password'  # ✅ Add this line
        )
        return connection
    except Error as e:
        print("Database connection error:", e)
        return None



