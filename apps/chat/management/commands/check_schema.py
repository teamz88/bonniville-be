from django.core.management.base import BaseCommand
from django.db import connection
from apps.chat.models import Conversation, Folder

class Command(BaseCommand):
    help = 'Check if the folder field exists in the conversation table'
    
    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            # Check if the folder field exists
            cursor.execute("PRAGMA table_info(chat_conversations);")
            columns = cursor.fetchall()
            
            folder_exists = any('folder' in str(col) for col in columns)
            
            if folder_exists:
                self.stdout.write(self.style.SUCCESS('Folder field exists in conversation table'))
            else:
                self.stdout.write(self.style.ERROR('Folder field does NOT exist in conversation table'))
                self.stdout.write('Available columns:')
                for col in columns:
                    self.stdout.write(f'  {col}')
                    
            # Try to create a test conversation
            try:
                test_conv = Conversation.objects.filter(user_id=1).first()
                if test_conv:
                    self.stdout.write(f'Test conversation folder: {test_conv.folder}')
                else:
                    self.stdout.write('No conversations found to test')
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Error accessing conversation: {e}'))