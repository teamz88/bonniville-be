from django.conf import settings
import logging
import requests

logger = logging.getLogger(__name__)

class NotificationService:
    """
    Service class for sending notifications via Ntfy.sh
    """
    
    def __init__(self):
        self.server_url = getattr(settings, 'NTFY_SERVER_URL', 'https://ntfy.hvacvoice.com')
        self.default_topic = getattr(settings, 'NTFY_DEFAULT_TOPIC', 'bonniville')
        self.default_email = getattr(settings, 'NTFY_DEFAULT_EMAIL', None)
    
    def send_notification(self, message, title=None, priority=3, tags=None, **kwargs):
        """
        General notification sending function
        """
        try:
            # Log the attempt
            logger.info(f"Attempting to send notification: {title} - {message[:100]}...")
            logger.debug(f"NTFY Config - Server: {self.server_url}, Topic: {self.default_topic}")
            
            # Prepare notification data
            url = f"{self.server_url}/{self.default_topic}"
            headers = {
                'Content-Type': 'text/plain; charset=utf-8',
            }
            
            if title:
                headers['Title'] = title
            if priority:
                headers['Priority'] = str(priority)
            if tags:
                headers['Tags'] = tags if isinstance(tags, str) else ','.join(tags)
            if self.default_email:
                headers['Email'] = self.default_email
            
            # Send notification
            response = requests.post(url, data=message.encode('utf-8'), headers=headers, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"Notification sent successfully: {title} - {message[:50]}...")
                return True
            else:
                logger.error(f"Notification failed with status {response.status_code}: {title} - {message[:50]}...")
                return False
                
        except Exception as e:
            logger.error(f"Exception sending notification: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def send_user_registration_notification(self, user_email, user_name=None):
        """
        Send notification when a new user registers
        """
        title = "New User Registration"
        message = f"New user registered: {user_email}"
        if user_name:
            message += f" ({user_name})"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=3,
            tags="user,registration,new"
        )
    
    def send_password_reset_notification(self, user_email):
        """
        Send notification when password reset is requested
        """
        title = "Password Reset Request"
        message = f"Password reset requested for: {user_email}"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=4,
            tags="password,reset,security"
        )
    
    def send_question_notification(self, user_email, question, user_id=None):
        """
        Send notification when a user asks a question
        """
        title = "New Question Asked"
        message = f"User asked a question: {user_email}"
        if question:
            message += f"\nQuestion: {question[:200]}{'...' if len(question) > 200 else ''}"
        
        if user_id:
            message += f"\nUser ID: {user_id}"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=4,  # High priority
            tags="question,user,chat"
        )
    
    def send_error_notification(self, error_message, error_type="General Error", user_info=None):
        """
        Send notification when an error occurs
        """
        title = f"Error: {error_type}"
        message = error_message
        
        if user_info:
            if isinstance(user_info, dict):
                if 'email' in user_info:
                    message += f"\nUser: {user_info['email']}"
                if 'user_id' in user_info:
                    message += f"\nUser ID: {user_info['user_id']}"
            else:
                message += f"\nUser: {user_info}"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=5,  # Max priority for errors
            tags="error,system,alert"
        )
    
    def send_success_notification(self, message, title="Success"):
        """
        Send success notification
        """
        return self.send_notification(
            message=message,
            title=title,
            priority=2,
            tags="success,system"
        )
    
    def send_warning_notification(self, message, title="Warning"):
        """
        Send warning notification
        """
        return self.send_notification(
            message=message,
            title=title,
            priority=4,
            tags="warning,system"
        )
    
    def send_rag_api_call_notification(self, user_email, question, api_type="chat", user_id=None):
        """
        Send notification when RAG API is called
        """
        title = f"RAG API Call - {api_type.title()}"
        message = f"User: {user_email}\nAPI Type: {api_type}"
        
        if question:
            message += f"\nQuestion: {question[:200]}{'...' if len(question) > 200 else ''}"
        
        if user_id:
            message += f"\nUser ID: {user_id}"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=3,
            tags="rag,api,chat"
        )
    
    def send_rag_feedback_notification(self, user_email, feedback_type, question, answer, user_id=None):
        """
        Send notification when RAG feedback is submitted
        """
        title = f"RAG Feedback - {feedback_type.title()}"
        message = f"User: {user_email}\nFeedback: {feedback_type}"
        
        if question:
            message += f"\nQuestion: {question[:100]}{'...' if len(question) > 100 else ''}"
        
        if answer:
            message += f"\nAnswer: {answer[:100]}{'...' if len(answer) > 100 else ''}"
        
        if user_id:
            message += f"\nUser ID: {user_id}"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=4,
            tags="rag,feedback,user"
        )
    
    def send_rag_file_upload_notification(self, user_email, file_name, file_size=None, user_id=None):
        """
        Send notification when file is uploaded to RAG
        """
        title = "RAG File Upload"
        message = f"User: {user_email}\nFile: {file_name}"
        
        if file_size:
            message += f"\nSize: {file_size} bytes"
        
        if user_id:
            message += f"\nUser ID: {user_id}"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=3,
            tags="rag,file,upload"
        )
    
    def send_rag_api_error_notification(self, user_email, error_message, api_type="chat", question=None, user_id=None):
        """
        Send notification when RAG API encounters an error
        """
        title = f"RAG API Error - {api_type.title()}"
        message = f"User: {user_email}\nAPI Type: {api_type}\nError: {error_message}"
        
        if question:
            message += f"\nQuestion: {question[:100]}{'...' if len(question) > 100 else ''}"
        
        if user_id:
            message += f"\nUser ID: {user_id}"
        
        return self.send_notification(
            message=message,
            title=title,
            priority=5,  # Max priority for API errors
            tags="rag,api,error"
        )

# Global notification service instance
notification_service = NotificationService()