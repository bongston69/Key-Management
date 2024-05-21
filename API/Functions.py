import requests
import platform
import hashlib
BASE_URL = 'http://127.0.0.1:5000'  # Change this to your server's URL when deployed


def generate_static_hwid():
    # Retrieve system information
    system_info = platform.uname()

    # Concatenate relevant system information to create a unique identifier
    hwid_str = f"{system_info.system}-{system_info.node}-{system_info.processor}-{system_info.machine}"

    # Hash the concatenated string to generate a static hardware ID
    hwid = hashlib.sha256(hwid_str.encode()).hexdigest()

    return hwid

def login(username, password):
    url = f"{BASE_URL}/login"
    data = {'username': username, 'password': password}
    response = requests.post(url, data=data)
    print(f"Raw Login Response: {response.text}")  # Debug print
    try:
        return response.json(), response.cookies
    except requests.exceptions.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None, None

def logout(cookies):
    url = f"{BASE_URL}/logout"
    response = requests.post(url, cookies=cookies)
    return response.json()

def generate_keys(number_of_keys, key_length, validity_length, cookies):
    url = f"{BASE_URL}/generate_keys"
    data = {
        'number_of_keys': number_of_keys,
        'key_length': key_length,
        'validity_length': validity_length
    }
    response = requests.post(url, json=data, cookies=cookies)
    return response.json()

def reset_hwid(license_key, cookies):
    url = f"{BASE_URL}/reset_hwid/{license_key}"
    response = requests.post(url, cookies=cookies)
    return response.json()

def update_time(license_key, new_length, cookies):
    url = f"{BASE_URL}/update_time/{license_key}"
    data = {'length': new_length}
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, json=data, headers=headers, cookies=cookies)
    return response.json()

def delete_key(license_key, cookies):
    url = f"{BASE_URL}/delete_key/{license_key}"
    response = requests.delete(url, cookies=cookies)
    return response.json()

def register(username, password, key, hwid):
    url = f"{BASE_URL}/register"
    data = {
        'username': username,
        'password': password,
        'key': key,
        'hwid': hwid
    }
    response = requests.post(url, json=data)
    return response.json()

def verify_user(username, password, hwid):
    url = f"{BASE_URL}/verify_user"
    data = {
        'username': username,
        'password': password,
        'hwid': hwid
    }
    response = requests.post(url, json=data)
    return response.json()



def main():
    # Admin credentials (replace with real credentials)
    admin_username = 'bong'
    admin_password = 'rip'
    HWID = str(generate_static_hwid())
#
    ## Log in as admin and get session cookies
    login_response, cookies = login(admin_username, admin_password)
    if login_response is None:
        print("Login failed. Please check the server logs and the login credentials.")
        return
#
    print(f"Login Response: {login_response}")
#
    if login_response.get('message') == 'Login successful':
       license_key = 'JRY37KITBW7BKEC6'  # Replace with a valid license key
       new_length = 30  # Example new validity length in days

         #Generate keys
       generate_response = generate_keys(5, 16, 30, cookies)
       print(f"Generate Keys Response: {generate_response}")

          #Reset HWID
        #reset_response = reset_hwid(license_key, cookies)
        #print(f"Reset HWID Response: {reset_response}")

        # Update time
        # update_response = update_time(license_key, new_length, cookies)
        # print(f"Update Time Response: {update_response}")

        # Delete key
        # delete_response = delete_key(license_key, cookies)
        # print(f"Delete Key Response: {delete_response}")

        # Logout
        # logout_response = logout(cookies)
        # print(f"Logout Response: {logout_response}")

    # Example non-admin calls
    # Register a new user
    #register_response = register('yoyo', 'rip', 'C9SMGTJ', HWID)
    #print(f"Register Response: {register_response}")

     #Verify user
    #verify_response = verify_user('yoyo', 'rip', generate_static_hwid())
    #print(f"Verify User Response: {verify_response}")

if __name__ == '__main__':
    main()
