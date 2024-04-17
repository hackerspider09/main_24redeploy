# Main Website (Backend)

---
#### Creating Virtual Enviornment:
```
virtualenv venv
```
#### Activating Virtual Env on Windows:
```
venv\Scripts\activate
```

#### Activating Virtual Env on Linux:
```
source venv/bin/activate
```

#### Installing Dependencies:
```
pip install -r requirements.txt
```
#### Run Python Development Server:
```
python manage.py runserver
```


> ### **API Endpoints**

| Endpoint | Method | Description |
|----------|--------|-------------|
|   /api/register/ | POST | Register a user|
|   /api/login/     | POST | Login a user and receive an access token and refresh token |
|   /api/refresh/  | POST | Used only when access token gets expired |
|   /api/password-reset/ | POST | Reset Password |
|   /api/password-reset-confirm/ | POST | POST UID and Token with a new password for confirmation |
|   /api/events/ | GET | List of all events |
|   /api/profile/  | GET | User Profile |
|   /api/leaderboard/ | GET | Leaderboard for Referral system |





