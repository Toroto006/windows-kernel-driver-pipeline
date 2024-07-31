import psycopg2
from psycopg2 import sql
from file_cache import file_cache

# Define the connection parameters
conn_params = {
    'dbname': 'pipeline',
    'user': 'pipeline',
    'password': 'CHANGE_PASSWORD',
    'host': 'COORDINATOR_IP',
    'port': '5432'
}

cached_conn = None
cached_cursor = None
 
@file_cache()
def run_query(query):
    global cached_conn, cached_cursor
    # Establish the connection
    try:
        # cache the connection
        if cached_conn is None:
            cached_conn = psycopg2.connect(**conn_params)
            cached_cursor = cached_conn.cursor()
        
        # Execute the query
        cached_cursor.execute(query)
        
        # Fetch all results
        results = cached_cursor.fetchall()
        
        return results
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def close_connection():
    if cached_conn is not None:
        cached_conn.close()
        cached_cursor.close()