# AI Agent Application

A full-stack AI Agent application with Django REST API backend and React.js frontend.

## Features

- **Smart AI Chatbot**: Text-to-text conversational interface
- **Cloud Storage**: MinIO integration for file uploads and storage
- **Custom Branding**: Configurable logo and colors
- **Role-Based Access**: Admin and User roles with different permissions
- **Analytics Dashboard**: Comprehensive analytics for admins
- **Secure Authentication**: JWT-based authentication

## Tech Stack

### Backend
- Django + Django REST Framework
- PostgreSQL database
- MinIO for file storage
- JWT authentication
- Swagger/OpenAPI documentation

### Frontend
- React.js with TypeScript
- Vite build tool
- shadcn/ui components
- Tailwind CSS
- Recharts for analytics

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- PostgreSQL
- MinIO server

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your database and MinIO credentials
```

5. Run migrations:
```bash
python manage.py migrate
```

6. Create superuser:
```bash
python manage.py createsuperuser
```

7. Start development server:
```bash
python manage.py runserver
```

### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start development server:
```bash
npm run dev
```

### File Storage Setup

The application now uses local file storage instead of MinIO. Files are stored in the `backend/media/uploads/` directory by default.

1. The storage directory will be created automatically when the first file is uploaded
2. You can customize the storage location by setting `FILE_STORAGE_ROOT` in your `.env` file
3. Set `FILE_STORAGE_MAX_SIZE` to configure the maximum storage limit (default: 1GB)

### PostgreSQL Setup

1. Install PostgreSQL
2. Create database:
```sql
CREATE DATABASE ai_agent_db;
CREATE USER ai_agent_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE ai_agent_db TO ai_agent_user;
```

## API Documentation

Once the backend is running, visit:
- Swagger UI: http://localhost:8000/swagger/
- ReDoc: http://localhost:8000/redoc/

## Project Structure

```
ai-agent/
├── backend/
│   ├── ai_agent/
│   │   ├── settings/
│   │   ├── urls.py
│   │   └── wsgi.py
│   ├── apps/
│   │   ├── authentication/
│   │   ├── chat/
│   │   ├── files/
│   │   └── analytics/
│   ├── requirements.txt
│   └── manage.py
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── services/
│   │   └── types/
│   ├── package.json
│   └── vite.config.ts
└── README.md
```

## Environment Variables

See `.env.example` files in both backend and frontend directories for required environment variables.

## Testing

### Backend Tests
```bash
cd backend
python manage.py test
```

### Frontend Tests
```bash
cd frontend
npm test
```

## Deployment

Refer to deployment guides in respective backend and frontend directories.

## License

MIT License