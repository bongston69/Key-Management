import requests

# Configuration
api_url = ''  # URL of your Flask API
admin_first_name = ''
admin_last_name = ''
admin_username = ''
admin_password = ''
admin_email = ''


def create_admin(first_name, last_name, username, password, email):
    response = requests.post(f'{api_url}/create_admin', json={
        'first_name': first_name,
        'last_name': last_name,
        'username': username,
        'password': password,
        'email': email
    })

    if response.status_code == 200:
        print(f'Success: {response.json()["message"]}')
    else:
        print(f'Error: {response.status_code} - {response.json()["message"]}')


if __name__ == '__main__':
    create_admin(admin_first_name, admin_last_name, admin_username, admin_password, admin_email)
