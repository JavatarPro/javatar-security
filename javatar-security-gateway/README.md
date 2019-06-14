# javatar-security-gateway

## description

This module should be used in api-gateway before all services are reached.
Only one module should be responsible of functions central login/logout and exchange token for all services.
In conjunction with security-filter module could also reject all requests on earlier stage 

This module depends on public-keys-storage implementation that should provide all public keys for realms that should 
be handled by this gateway. The aim to verify signature and get newer token if current token close to expiration.

Also gateway modules depends on token-storage implementation to save all issued tokens in highly available storage and 
also to delete all tokens to logout.

## usage example


    javatar:
      security:
        gateway:
          login:
            enabled: true
            redirect-url: /login.html
          logout:
            enabled: true
            redirect-url: /logout.html
        apply-urls:
          - /order-service/*
          - /payment-service/*
        ignore-urls:
          - /login
        identity-provider:
          url: ${keycloak.url}
          client: api-gateway-service
          secret: b3e42833-a43a-4dd5-a962-5ddde60ec5b9
          realm: dev
        public-keys-storage: in-memory
        token-storage: redis
        storage:
          in-memory:
            public-keys:
              dev: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApDO/xCzSgTbqxTpSz4nhIS3vcxO/RhdbZ7tLZT39RTh53XOxUUa+/CQB9WFNmfiUep3waf4pK/OGCwiuxZN+8fQru22vkMbd/pJMW2vndRjRc12dAkcEzlQdRUEBfHxVA0OjTtWNNKsY45kPMsSu5Bu1BRFX2wfpz0lZAjy/UNxxhWvfX/ZgP6a75zaaweN07W+p6WbQClTVPMsskY3R5NLzgPrEyj845Ej++KxdioNE3ybiUghaBuUXYJxOop4sst7pGCwsx0FkweeYam4z7rRQKn6lf9gIz64HbLQhQ/W/JY36xCOmZBhOgW/DOUnYosnhvMa0D471KVnxu0h/SwIDAQAB
          redis:
            host: ${redis.host}
            port: ${redis.port}
            password: ${redis.password}
            expiration: PT1M15S

## troubleshooting

### debug example

    url=localhost:8080
    file=javatar-security-gateway/src/test/resources/gateway/login-request.json
    curl -v -X POST -H "Content-Type: application/json" ${url}/login --data @${file}
    
    