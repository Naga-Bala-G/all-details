import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'eXDQ3OkMSAXOZeC3S4r4baCsmA0WUpp9')
    OIDC_CLIENT_SECRETS = 'keycloak.json'  # Path to Keycloak config JSON
    OIDC_SCOPES = ["openid", "email", "profile"]
    OIDC_RESOURCE_CHECK_AUD = True
    OIDC_INTROSPECTION_AUTH_METHOD = 'client_secret_post'
    OIDC_VALID_ISSUERS = ["http://localhost:8080/auth/realms/{your_realm}"]

class ProductionConfig(Config):
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True
