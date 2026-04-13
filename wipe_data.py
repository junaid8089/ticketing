import psycopg2
from psycopg2 import sql

DB_HOST = "202.164.150.222"
DB_PORT = "15044"
DB_USER = "postgres"
DB_PASS = "123456"
DB_NAME = "junaiddb1"

def wipe_and_reseed():
    print("Wiping all existing data...")
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT
    )
    conn.autocommit = True
    cursor = conn.cursor()
    
    # Check if users table exist, if not we will let next query fail silently
    try:
        cursor.execute("DROP TABLE IF EXISTS tickets, ticket_replies, ticket_attachments, ticket_audit_log, users CASCADE;")
        print("Dropped all tables securely.")
    except Exception as e:
        print(f"Error dropping tables: {e}")
        
    print("Re-creating users table and seeding default Manager...")
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, 
            name VARCHAR(255), 
            email VARCHAR(255) UNIQUE, 
            password VARCHAR(255),
            role VARCHAR(50), 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # By default, use password 'admin' for Manager. The user asked for "default login set as manager".
    cursor.execute("""
        INSERT INTO users (name, email, password, role) 
        VALUES ('Admin Manager', 'manager@nexus.ent', 'admin', 'Manager') 
        ON CONFLICT (email) DO NOTHING;
    """)
    
    print("Wipe and reset successful. Default manager login: email [manager@nexus.ent], password [admin]")
    cursor.close()
    conn.close()

if __name__ == "__main__":
    wipe_and_reseed()
