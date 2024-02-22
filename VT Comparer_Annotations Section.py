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
        return md5_hash, sha1_hash, sha256_hash, ssdeep_hash, "VirusTotal"
    elif response.status_code == 404:
        print(f"Hash '{hash_value}' not found in VirusTotal.")
        return None, None, None, None, None
    else:
        print("Error occurred while querying VirusTotal for hash:", hash_value)
        return None, None, None, None, None

def save_to_file(hash_values_info):
    with open("hash_info.txt", "w") as file:
        for hash_value, info in hash_values_info.items():
            file.write(f"Hash: {hash_value}\n")
            file.write(f"Source: {info[4]}; MD5: {info[0]}; SHA-1: {info[1]}; SHA-256: {info[2]}; SSDEEP: {info[3]}\n\n")

if __name__ == "__main__":
    original_source = input("Enter the original source for the hashes: ").strip()
    hash_values_info = {}
    while True:
        hash_value = input("Enter the hash value (or press Enter to finish): ").strip()
        if not hash_value:
            break
        md5_hash, sha1_hash, sha256_hash, ssdeep_hash, source = retrieve_hash_info(hash_value.strip())
        if md5_hash and sha1_hash and sha256_hash and ssdeep_hash:
            if hash_value == original_source:
                hash_values_info[hash_value.strip()] = (md5_hash, sha1_hash, sha256_hash, ssdeep_hash, original_source)
            else:
                hash_values_info[hash_value.strip()] = (md5_hash, sha1_hash, sha256_hash, ssdeep_hash, "VirusTotal")

    if hash_values_info:
        print("Hash information:")
        for hash_value, info in hash_values_info.items():
            print(f"Hash: {hash_value}")
            print(f"Source: {info[4]}; MD5: {info[0]}; SHA-1: {info[1]}; SHA-256: {info[2]}; SSDEEP: {info[3]}")
            print()

        save_to_file(hash_values_info)
        print("Hash information saved to hash_info.txt")
    else:
        print("No valid hash information retrieved.")
