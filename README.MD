### Preview deployed version
#### Login 
``` http
POST /api/login HTTP/1.1
Host: jwt-demo.vercel.app
Content-Type: application/json
Content-Length: 52

{
    "username": "admin",
    "password": "admin"
}
```

#### Main
``` http
GET /api/main HTTP/1.1
Host: jwt-demo.vercel.app
Authorization: Bearer {{access_token}}
```

#### Refresh token
``` http
POST /api/token HTTP/1.1
Host: jwt-demo.vercel.app
Content-Type: application/json
Content-Length: 144

{
    "token": "{{refresh_token}}"
}
```

#### Retract token
``` http
DELETE /api/token HTTP/1.1
Host: jwt-demo.vercel.app
Content-Type: application/json
Content-Length: 144

{
    "token": "{{refresh_token}}"
}
```

### Run locally
#### Before you go
`.env` file should be provided with varibales:
``` env
ACCESS_TOKEN_SECRET='your_secret'
REFRESH_TOKEN_SECRET='your_different_secret'
DB_URI='mongodb_uri'
DB_NAME='db_name'
DB_USER='db_user'
DB_PASS='db_pass'
```

Run `npm run devStart`