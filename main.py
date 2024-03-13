# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import requests
from config import API_KEY, API_FILE_URL, API_FILE_ANALYSES_URL


file_path = "invoice-42369643.xlsm"
headers = {"accept": "application/json", "x-apikey": API_KEY}
payload = {"file": "/home/kar/Downloads/invoice-42369643.xlsm"}

# Step 1. Unzip file

# Step 2. Upload file on VirusTotal server
with open(file_path, "rb") as file:
    files = {"file": (file_path, file)}
    response = requests.post(API_FILE_URL, headers=headers, files=files)
    _id = response.json()["data"]["id"]







# Step 3. Analyze file on malware

url = "{}/{}".format(API_FILE_ANALYSES_URL, _id)
response = requests.get(url, headers=headers)
report = response.json()




# creat spisok dangeres


# data_danger = [list for list in report['data']['attributes']['results'].values()]
# print(*data_danger, sep="\n")

list_pd = report['data']['attributes']['results'] # для заполнения матрицы
data_danger_pd= [[list['engine_name'], list['result']] for list in list_pd .values() if list['result']]
x_data_danger_pd = sorted(list({x[0] for x in data_danger_pd}))
y_data_danger_pd = sorted(list({y[1] for y in data_danger_pd}))
# print(x_data_danger_pd, y_data_danger_pd)
# print(*data_danger_pd, sep="\n")
# print(data_danger_pd)

matrix = [["-"]*len(x_data_danger_pd ) for _ in range(len(y_data_danger_pd ))]
# print(*matrix, sep="\n")
# print(data_danger_pd)

for y in range(len(y_data_danger_pd)):
    print(y_data_danger_pd[y])
    for x in range(len(x_data_danger_pd)):
        for antivirus, virus in data_danger_pd:

            if x_data_danger_pd[x] == antivirus and y_data_danger_pd[y] == virus:

                if "-" == matrix[y][x]:
                    matrix[y][x] = 1
                else:
                    matrix[y][x] +=1

# print(*matrix, sep="\n")


import pandas as pd
tadl = pd.DataFrame(matrix, index=y_data_danger_pd, columns = x_data_danger_pd)
print(tadl)















# url_behaviors = "{}/{}/behaviours".format(API_FILE_URL, _id)
# print(url_behaviors)
# # response = requests.get(url_behaviors, headers=headers)
# # print(response.text)
