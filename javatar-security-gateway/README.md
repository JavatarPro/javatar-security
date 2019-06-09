
    url=localhost:8080
    file=src/test/resources/gateway/login-request.json
    
    curl -v -X POST ${url}/login --data @${file}