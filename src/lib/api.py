import base64
import json
import os
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

class BWWrapperError(Exception):
    def __init__(self, msg):
        self.msg = msg
    
    def __repr__(self):
        return self.msg
        
class BWWrapperWrongPasswordError(Exception):
    pass
        

class Wrapper(object):
    def __init__(self, email=None, password=None):
        if not self.bitwarden_cli_installed():
            raise BWWrapperError()
        
        self.environ = os.environ
        location = self.get_db_location(sys.platform)
        self.open_db(location)
        self.unlocked = False
        
    def unlock(self, email=None, password=None):
        try:
            self.session = self.get_session(email=email, password=password)
        except BWWrapperWrongPasswordError:
            self.unlocked = False
            return False
        self.unlocked = bool(self.session) and bool(self.user)
        return self.unlocked

    def needs_email(self):
        return not bool(self.extract_logged_user())
    
    def get_db_location(self, platform):
        """
        This is a port of
        https://github.com/bitwarden/cli/blob/783e7fc8348d02853983211fa28dd8448247ba92/src/bw.ts#L67-L75
        """
        env = self.environ.get("BITWARDENCLI_APPDATA_DIR")
        if env:
            path = os.path.expanduser(env)

        elif platform == "darwin":
            path = os.path.expanduser("~/Library/Application Support/Bitwarden CLI")

        elif platform == "win32":
            path = os.path.expandvars("%AppData%/Bitwarden CLI")

        else:
            path = os.path.expanduser("~/snap/bw/current/.config/Bitwarden CLI")
            if not os.path.exists(path):
                path = os.path.expanduser("~/.config/Bitwarden CLI")

        return os.path.join(path, "data.json")


    def open_db(self, db_location):
        try:
            with open(db_location, "r") as file:
                self.db = json.load(file)
        except IOError:
            self.db = {}
        
        self.user = self.extract_logged_user()

    def extract_logged_user(self):
        return self.db.get("userEmail")

    def bitwarden_cli_installed(self):
        return bool(shutil.which("bw")) 
        
    def try_get_session(self):
        if "BW_SESSION" in self.environ:
            try:
                # Check that the token works.
                self.bw("sync", session=False)
            except ValueError:
                pass
            else:
                self.session = self.environ["BW_SESSION"]
                self.unlocked = True
                return self.session
        return None

    def get_session(self, email=None, password=None):
        self.session = self.ask_for_session(bool(self.user), email, password)
        if self.user is None and self.session:
            self.open_db()
        return self.session
        
    def ask_for_session(self, is_authenticated, email, password):
        if password is None:
            raise BWWrapperError("No password specified!")
        if is_authenticated:
            command = ["unlock", "--raw", password]
        else:
            if email is None:
                raise BWWrapperError("No email specified!")
            command = ["login", "--raw", email, password]
        result = self.bw(*command, session=False)
        return result


    def wrong_password(self, output):
        if "Username or password is incorrect" in output:
            return True
        elif "Invalid master password" in output:
            return True
        return False


    def bw(self, *args, session=True):
        cli_args = ["bw"]
        if session:
            cli_args += ["--session", self.session]

        cli_args += list(args)
        print(cli_args)

        try:
            result = subprocess.run(
                cli_args, stdout=subprocess.PIPE, check=True
            ).stdout.strip()
        except subprocess.CalledProcessError as exc:
            output = exc.stdout.decode("utf-8")
            if self.wrong_password(output):
                raise BWWrapperWrongPasswordError("Wrong Password")
            raise ValueError(output) from exc

        return result


class Query(object):
    def __init__(self, bw):
        self.bw = bw

    def extract_domain_name(self, full_url):
        full_domain = urlsplit(full_url).netloc
        if not full_domain:
            return full_url

        return ".".join(full_domain.split(".")[-2:])

    def match_credentials(self, credentials, username):
        for cred in credentials:
            login = cred.get("login") or {}
            cred_username = login.get("username")
            if cred_username == username and "password" in login:
                yield cred

    def encode(self, payload):
        return base64.b64encode(json.dumps(payload).encode("utf-8"))

    def get_password(self, service, username):
        credentials = self.search(service)
        matches = list(self.match_credentials(credentials, username))
        return matches
        
    def search(self, service):
        search = self.extract_domain_name(service)
        results = self.bw.bw("list", "items", "--search", search)
        return json.loads(results)

    def add(self, args):
        #{"organizationId":null,"folderId":null,"type":1,"name":"Item name","notes":"Some notes about this item.","favorite":false,"fields":[],"login":null,"secureNote":null,"card":null,"identity":null}
        template_str = self.bw.bw("get", "template", "item")
        
        if args.type == "pass":
            typ = 1
        elif args.type == "note":
            typ = 2
            args.secureNote = {"type": 0}
        elif args.type == "cc":
            typ = 3
        else:
            typ = 4

        login = None
        if args.username or args.password or args.url:
            login = {
                "uris": [{"match": None, "uri": service}],
                "username": username,
                "password": password, }
        
        folderid = None
        
        template = json.loads(template_str)
        template.update(
            {
                "type": typ,
                "folderId": folderid,
                "name": args.name,
                "notes": args.notes,
                "login": login,
                "secureNote": args.secureNote,
            }
        )

        payload = self.encode(template)

        self.bw.bw("create", "item", payload)
        print("Created.")

    def set_password(self, service, username, password):
        template_str = self.bw.bw("get", "template", "item")

        template = json.loads(template_str)
        template.update(
            {
                "name": service,
                "notes": None,
                "login": {
                    "uris": [{"match": None, "uri": service}],
                    "username": username,
                    "password": password,
                },
            }
        )

        payload = self.encode(template)

        self.bw.bw("create", "item", payload)
        print("Created.")
        
    def real_delete_credential(self, credential):
        self.bw.bw("delete", "item", credential["id"])

    def delete_password_dry(self, service, username):
        search = self.extract_domain_name(service)

        result = self.bw.bw("get", "item", search)

        credential = json.loads(result)
        return credential

