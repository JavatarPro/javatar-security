
    url=localhost:8080
    file=src/test/resources/gateway/login-request.json
    
    curl -v -X POST -H "Content-Type: application/json" ${url}/login --data @${file}
    
    