#!/usr/bin/env python
import os
import sys
import django
from django.db import connection

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ai_agent.settings')
django.setup()

def fix_schema():
    with connection.cursor() as cursor:
        try:
            # Check if folder field exists
            cursor.execute("PRAGMA table_info(chat_conversations);")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'folder_id' not in columns:
                print("Adding folder_id field to chat_conversations table...")
                
                # Create folders table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS chat_folders (
                        id TEXT PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        name VARCHAR(100) NOT NULL,
                        description TEXT,
                        color VARCHAR(7) DEFAULT '#6B7280',
                        created_at DATETIME NOT NULL,
                        updated_at DATETIME NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES auth_user (id)
                    );
                """)
                
                # Add folder_id column to conversations table
                cursor.execute("""
                    ALTER TABLE chat_conversations 
                    ADD COLUMN folder_id TEXT 
                    REFERENCES chat_folders(id) ON DELETE SET NULL;
                """)
                
                print("Schema fixed successfully!")
            else:
                print("Folder field already exists.")
                
        except Exception as e:
            print(f"Error fixing schema: {e}")
            
if __name__ == '__main__':
    fix_schema()