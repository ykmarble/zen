#!/usr/bin/env python3

from typing import List
import requests as rq
import yaml
import urllib
import time
import pickle
import os
import random


CREDENTIAL_FILE = "credential.yml"
URLDB_FILE = "imgurls.dat"


class Credential:
    def __init__(self):
        self.client_id = None
        self.client_secret = None
        self.access_token = None
        self.refresh_token = None

    def auth_header(self):
        assert self.access_token
        return {
            "Authorization": "Bearer {}".format(self.access_token)
        }


def auth(cred: Credential) -> Credential:
    auth_endpoint = "https://accounts.google.com/o/oauth2/auth"
    token_endpoint = "https://www.googleapis.com/oauth2/v3/token"
    query = {
        "client_id": cred.client_id,
        "response_type": "code",
        "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        "access_type": "offline",
        "approval_prompt": "force",
        "scope": "https://www.googleapis.com/auth/photoslibrary.readonly",
    }
    url = auth_endpoint + "?" + urllib.parse.urlencode(query)
    print(url)
    code = input("code: ")
    query2 = {
        "code": code,
        "client_id": cred.client_id,
        "client_secret": cred.client_secret,
        "response_type": "code",
        "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        "grant_type": "authorization_code",
        "access_type": "offline",
    }
    res = rq.post(token_endpoint, query2)
    res.raise_for_status()
    resj = res.json()
    cred.access_token = resj["access_token"]
    cred.refresh_token = resj["refresh_token"]
    return cred


def refresh(cred: Credential) -> Credential:
    endpoint = "https://www.googleapis.com/oauth2/v3/token"
    query = {
        "refresh_token": cred.refresh_token,
        "client_id": cred.client_id,
        "client_secret": cred.client_secret,
        "grant_type": "refresh_token"
    }
    res = rq.post(endpoint, query)
    res.raise_for_status()
    cred.access_token = res.json()["access_token"]
    return cred


def load_credential(path: str) -> Credential:
    with open(path) as f:
        cred_dic = yaml.load(f)
    cred = Credential()
    cred.client_id     = cred_dic["client_id"]
    cred.client_secret = cred_dic["client_secret"]
    if "access_token" in cred_dic and "refresh_token" in cred_dic:
        cred.access_token  = cred_dic["access_token"]
        cred.refresh_token = cred_dic["refresh_token"]
    return cred


def dump_credential(cred: Credential, path: str):
    cred_dic = {
        "client_id"    : cred.client_id,
        "client_secret": cred.client_secret
    }
    if cred.access_token and cred.refresh_token:
        cred_dic["access_token"]  = cred.access_token
        cred_dic["refresh_token"] = cred.refresh_token
    with open(path, "w") as f:
        f.write(yaml.dump(cred_dic, default_flow_style=False))


def album_list(cred: Credential) -> List[str]:
    endpoint = "https://photoslibrary.googleapis.com/v1/albums"
    res = rq.get(endpoint, headers=cred.auth_header())
    res.raise_for_status()
    return res.json()["albums"]

def album_media(cred: Credential, album_id: str) -> List[str]:
    endpoint = "https://photoslibrary.googleapis.com/v1/mediaItems:search"
    query = {
        "albumId": album_id,
        "pageSize": 100,
    }
    res = rq.post(endpoint, data=query, headers=cred.auth_header())
    res.raise_for_status()
    resj = res.json()
    media = resj["mediaItems"]
    while "nextPageToken" in resj:
        query["pageToken"] = resj["nextPageToken"]
        res = rq.post(endpoint, data=query, headers=cred.auth_header())
        res.raise_for_status()
        resj = res.json()
        media.extend(resj["mediaItems"])
        time.sleep(0.5)
    return media


def main():
    cred = load_credential(CREDENTIAL_FILE)
    if cred.access_token is None:
        print("Get access token.")
        auth(cred)
        dump_credential(cred, CREDENTIAL_FILE)
        print("Saved token.")

    if not os.path.exists(URLDB_FILE):
        print("Generate image url db.")
        print("Fetching album list...")
        album = album_list(cred)
        print("Fetching url list...")
        media = album_media(cred, album[0]["id"])
        media_urls = [m["baseUrl"] for m in media]
        with open(URLDB_FILE, "wb") as f:
            pickle.dump(media_urls, f)
    else:
        with open(URLDB_FILE, "rb") as f:
            media_urls = pickle.load(f)

    print("Choise new image.")
    baseurl = random.choice(media_urls)
    print(baseurl + "=w1024")


if __name__ == '__main__':
    main()
