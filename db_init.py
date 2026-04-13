import os
import psycopg2
from psycopg2 import sql

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

DB_HOST = os.environ.get("DB_HOST", "202.164.150.222")
DB_PORT = os.environ.get("DB_PORT", "15044")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "123456")
DB_NAME = os.environ.get("DB_NAME", "junaiddb1")

def initialize_database():
    print(f"Connecting to {DB_NAME} at {DB_HOST}:{DB_PORT} as {DB_USER}...")
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT
        )
        conn.autocommit = True
        cursor = conn.cursor()
        print("Connected successfully!")
        
        # SQL Commands to create tables
        create_tables_sql = """
        -- 1. tickets
        CREATE TABLE IF NOT EXISTS tickets (
            id SERIAL PRIMARY KEY,
            public_ticket_id VARCHAR(50) UNIQUE NOT NULL,
            customer_name VARCHAR(255) NOT NULL,
            customer_email VARCHAR(255) NOT NULL,
            cc_emails TEXT,
            phone VARCHAR(50),
            priority VARCHAR(50),
            category VARCHAR(100),
            subject VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'New',
            assigned_to VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            closed_at TIMESTAMP
        );

        -- 2. ticket_replies
        CREATE TABLE IF NOT EXISTS ticket_replies (
            id SERIAL PRIMARY KEY,
            ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
            sender_type VARCHAR(50) NOT NULL, -- 'Customer' or 'Agent'
            sender_email VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            attachment_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- 3. ticket_attachments
        CREATE TABLE IF NOT EXISTS ticket_attachments (
            id SERIAL PRIMARY KEY,
            ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
            file_name VARCHAR(255) NOT NULL,
            file_path TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- 4. ticket_audit_log
        CREATE TABLE IF NOT EXISTS ticket_audit_log (
            id SERIAL PRIMARY KEY,
            ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
            action VARCHAR(255) NOT NULL,
            performed_by VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        print("Executing schema creation...")
        cursor.execute(create_tables_sql)
        print("Tables created successfully (tickets, ticket_replies, ticket_attachments, ticket_audit_log)!")

    except Exception as e:
        print(f"Error connecting or executing queries: {e}")
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()
            print("PostgreSQL connection closed.")

if __name__ == "__main__":
    initialize_database()
