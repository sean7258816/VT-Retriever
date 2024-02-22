import requests

API_KEY = '61a76a7ffa288b851f3b659fd217dd8ed29456ca502cb0144172d89f719d45a3'

def retrieve_hash_info(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        md5_hash = data['data']['attributes']['md5']
        sha1_hash = data['data']['attributes']['sha1']
        sha256_hash = data['data']['attributes']['sha256']
        ssdeep_hash = data['data']['attributes']['ssdeep']
        return md5_hash, sha1_hash, sha256_hash, ssdeep_hash
    elif response.status_code == 404:
        print(f"Hash '{hash_value}' not found in VirusTotal.")
        return None, None, None, None
    else:
        print("Error occurred while querying VirusTotal for hash:", hash_value)
        return None, None, None, None

if __name__ == "__main__":
    hash_values = []
    while True:
        hash_value = input("Enter the hash value (or press Enter to finish): ").strip()
        if not hash_value:
            break
        hash_values.append(hash_value)

    for hash_value in hash_values:
        md5_hash, sha1_hash, sha256_hash, ssdeep_hash = retrieve_hash_info(hash_value.strip())
        if md5_hash and sha1_hash and sha256_hash and ssdeep_hash:
            print("Hash information for:", hash_value)
            print(f"MD5: {md5_hash}")
            print(f"SHA1: {sha1_hash}")
            print(f"SHA256: {sha256_hash}")
            print(f"SSDEEP: {ssdeep_hash}")
            print()
        else:
            print("No valid hash information retrieved for:", hash_value)
