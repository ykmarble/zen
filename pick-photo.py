#!/usr/bin/env python3

import requests as rq
import yaml
import urllib
import time
import pickle
import os
import random
from typing import List


CREDENTIAL_FILE = "credential.yml"
URLDB_FILE = "imgurls.dat"


class Credential:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.refresh_token = None
        self.expire_at = 0

    def set_access_token(self, access_token: str, expire_in: float):
        """
        Set new access token with lifetime.
        `expire_in` means lifetime from now.
        """
        self.access_token = access_token
        utc_now = time.time()
        self.expire_at = utc_now + expire_in

    def has_valid_token(self):
        """
        Check if this credential has valid token.
        """
        if self.access_token is None:
            return False
        return time.time() < self.expire_at

    def auth_header(self):
        """
        Generate authorization header.
        Set this as http reqest header to access oauth2 protected resources.
        """
        assert self.access_token
        return {
            "Authorization": "Bearer {}".format(self.access_token)
        }


def auth(cred: Credential) -> Credential:
    """
    Get access token and refresh token and update credential by them.
    Authentication flow (e.g. navigate user to authentication page) is included.
    """

    auth_endpoint = "https://accounts.google.com/o/oauth2/auth"
    token_endpoint = "https://www.googleapis.com/oauth2/v3/token"

    # first, ask user to visit authentication page
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
    # server generates code for getting token if user approved request
    code = input("code: ")

    # second, get access token (and refresh token) with the code
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

    # update and return credential
    cred.access_token = resj["access_token"]
    cred.refresh_token = resj["refresh_token"]
    return cred


def refresh(cred: Credential) -> Credential:
    """
    Reflesh access token.
    """
    endpoint = "https://www.googleapis.com/oauth2/v3/token"
    query = {
        "refresh_token": cred.refresh_token,
        "client_id": cred.client_id,
        "client_secret": cred.client_secret,
        "grant_type": "refresh_token"
    }
    res = rq.post(endpoint, query)
    res.raise_for_status()
    resj = res.json()
    cred.set_access_token(resj["access_token"], float(resj["expires_in"]))

    return cred


def load_credential(path: str) -> Credential:
    """
    Load credential from yml file.
    """
    with open(path) as f:
        cred_dic = yaml.load(f)
    cred = Credential(cred_dic["client_id"], cred_dic["client_secret"])
    if "access_token" in cred_dic and "refresh_token" in cred_dic:
        cred.access_token  = cred_dic["access_token"]
        cred.refresh_token = cred_dic["refresh_token"]
        cred.expire_at = cred_dic["expire_at"]
    return cred


def dump_credential(cred: Credential, path: str):
    """
    Dump credential to yml file.
    """
    with open(path) as f:
        cred_dic = yaml.load(f)
    cred_dic["client_id"] = cred.client_id
    cred_dic["client_secret"] = cred.client_secret
    if cred.access_token and cred.refresh_token:
        cred_dic["access_token"]  = cred.access_token
        cred_dic["refresh_token"] = cred.refresh_token
        cred_dic["expire_at"] = cred.expire_at
    with open(path, "w") as f:
        f.write(yaml.dump(cred_dic, default_flow_style=False))


def album_list(cred: Credential) -> List[str]:
    """
    Get all album metadata in the account.
    """
    endpoint = "https://photoslibrary.googleapis.com/v1/albums"
    res = rq.get(endpoint, headers=cred.auth_header())
    res.raise_for_status()
    return res.json()["albums"]


def album_media(cred: Credential, album_id: str) -> List[str]:
    """
    Get all images or videos metadata in the specified album.
    """
    endpoint = "https://photoslibrary.googleapis.com/v1/mediaItems:search"
    query = {
        "albumId": album_id,
        "pageSize": 100,      # at most 100 entries are included in one responce
    }
    res = rq.post(endpoint, data=query, headers=cred.auth_header())
    res.raise_for_status()  # raise error if request failed
    resj = res.json()
    media = resj["mediaItems"]

    while "nextPageToken" in resj:  # there is more entries actually
        query["pageToken"] = resj["nextPageToken"]
        res = rq.post(endpoint, data=query, headers=cred.auth_header())
        res.raise_for_status()
        resj = res.json()
        media.extend(resj["mediaItems"])
        time.sleep(0.5)

    return media


def postslack(endpoint: str, imgurl: str):
    header = {
        "Content-type": "application/json",
    }
    query = {
        "username": "一日一善",
        "icon_emoji": ":amcg:",
        "channel": "playground",
        "text": f"<{imgurl}|今日の一枚>",
    }

    res = rq.post(endpoint, json=query, headers=header)
    res.raise_for_status()


def main():
    cred = load_credential(CREDENTIAL_FILE)
    if cred.access_token is None:
        print("Get access token.")
        auth(cred)
        dump_credential(cred, CREDENTIAL_FILE)
        print("Saved token.")

    if not cred.has_valid_token():
        print("Refresh token.")
        refresh(cred)
        assert cred.has_valid_token()
        dump_credential(cred, CREDENTIAL_FILE)
        try:
            os.remove(URLDB_FILE)
        except OSError:
            pass

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
    url = random.choice(media_urls) + "=w512"
    print(url)
    with open(CREDENTIAL_FILE) as f:
        slack_endpoint = yaml.load(f)["slack_endpoint"]
    postslack(slack_endpoint, url)


if __name__ == '__main__':
    main()
