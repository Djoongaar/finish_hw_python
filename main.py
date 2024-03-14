# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import requests
import numpy as np
import pandas as pd
import json
from config import API_KEY, API_FILE_URL, API_FILE_ANALYSES_URL, FILE_PATH


def unzip_file(file_path):
    """
    Unzip file
    :param file_path:
    :return: file_path
    """
    pass


def upload_file(filepath: str) -> int:
    """
    Upload file on VirusTotal server
    :param filepath:
    :return: id of the file
    """
    headers = {"accept": "application/json", "x-apikey": API_KEY}

    with open(filepath, "rb") as file:
        files = {"file": (filepath, file)}
        response = requests.post(API_FILE_URL, headers=headers, files=files)
        return response.json()["data"]["id"]


def analyze_file(local_file_id: int) -> dict:
    """
    Analyze file on malware
    :param local_file_id:
    :return:
    """
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    url = "{}/{}".format(API_FILE_ANALYSES_URL, local_file_id)

    response = requests.get(url, headers=headers)
    return response.json()


def create_dataframe(report_path: str):
    """
    Create pandas dataframe from json
    :param report_path: str
    :return: Pandas DF
    df = [
        [0, 1, 0, 1, 0, 0, 0, 1],
        [1, 0, 1, 1, 0, 1, 0, 0],
        [...]
    ]
    """
    with open(report_path) as f:
        report = json.load(f)["data"]["attributes"]["results"]
    result = []
    for software_name, report in report.items():
        if_detected = None if report["result"] is None else "Detected"

        result.append([
            report["engine_name"],
            if_detected,
            report["result"]
        ])
    return pd.DataFrame(result, columns=["engine", "if_detected", "malware"])


def create_report(dataframe):
    dataframe.to_csv("data.csv", index=False, sep="\t")

    return 0


create_report(create_dataframe("data.json"))
