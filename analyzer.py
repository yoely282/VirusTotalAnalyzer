import requests
import time
import json
from security import API_KEY, FILE_PATH


def upload_file(api_key, file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': api_key
    }
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, headers=headers, files=files)
    return response.json()

def get_analysis(api_key, file_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(url, headers=headers)
    return response.json()

def main():
    upload_response = upload_file(API_KEY, FILE_PATH)
    file_id = upload_response['data']['id']

    print('File uploaded, waiting for analysis...')
    time.sleep(60)  # wait for analysis

    analysis_response = get_analysis(API_KEY, file_id)
    with open('analysis_report.json', 'w') as report_file:
        json.dump(analysis_response, report_file, indent=4)

    print('Analysis report saved to analysis_report.json')

if __name__ == '__main__':
    main()
