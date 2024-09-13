from flask import Flask, request, jsonify
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakError
import json

app = Flask(__name__)

# Keycloak configuration
keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth/",
                                 client_id="sso_client",
                                 realm_name="my_realm",
                                 client_secret_key="eXDQ3OkMSAXOZeC3S4r4baCsmA0WUpp9")

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        # Authenticate with Keycloak
        token = keycloak_openid.token(username, password)
        userinfo = keycloak_openid.userinfo(token['access_token'])

        # Include roles and permissions in the response
        response = {
            'access_token': token['access_token'],
            'refresh_token': token['refresh_token'],
            'roles': userinfo.get('roles', []),
            'permissions': userinfo.get('permissions', [])
        }
        return jsonify(response), 200
    except KeycloakError as e:
        return jsonify({"error": str(e)}), 401


@app.route('/api/auth/userinfo', methods=['GET'])
def userinfo():
    try:
        token = request.headers.get('Authorization').split()[1]
        userinfo = keycloak_openid.userinfo(token)
        return jsonify(userinfo), 200
    except KeycloakError as e:
        return jsonify({"error": str(e)}), 401


@app.route('/api/auth/refresh-token', methods=['POST'])
def refresh_token():
    try:
        data = request.json
        refresh_token = data.get('refresh_token')

        new_token = keycloak_openid.refresh_token(refresh_token)
        return jsonify({
            'access_token': new_token['access_token'],
            'refresh_token': new_token['refresh_token']
        }), 200
    except KeycloakError as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/rbac/roles', methods=['POST'])
def create_update_role():
    try:
        data = request.json
        role_name = data.get('role_name')
        permissions = data.get('permissions')
        cloud_provider = data.get('cloud_provider')  # Process based on cloud provider

        # Logic to create or update role with Keycloak goes here

        return jsonify({"message": f"Role '{role_name}' created/updated for {cloud_provider}."}), 200
    except KeycloakError as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/rbac/roles', methods=['GET'])
def get_roles():
    try:
        cloud_provider = request.args.get('cloud_provider')

        # Logic to retrieve roles based on cloud provider goes here

        roles = []  # Example
        return jsonify({"roles": roles}), 200
    except KeycloakError as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/rbac/assign-role', methods=['POST'])
def assign_role():
    try:
        data = request.json
        username = data.get('username')
        role_name = data.get('role_name')
        cloud_provider = data.get('cloud_provider')

        # Logic to assign role to user in Keycloak

        return jsonify({"message": f"Role '{role_name}' assigned to {username} for {cloud_provider}."}), 200
    except KeycloakError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)
