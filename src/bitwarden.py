from lib import api
import os, sys
import getpass

class UI(object):
    def __init__(self, bw):
        self.bw = bw
        self.query = api.Query(bw)
    
    def select_from_multiple_matches(self, matches):
        print("Multiple credential found. Which one would you like to use ?")
        mapping = {str(i): v for i, v in enumerate(matches, 1)}
        print(self.display_credentials(mapping))
        value = input("Your choice ? ")
        return mapping[value]

    def select_single_match(self, matches):
        if len(matches) == 0:
            return

        if len(matches) == 1:
            match, = matches
            try:
                return match
            except KeyError:
                return None

        raise ValueError("Multiple matches")
        
    def display_credential(self, match, password=False):
        if match['type'] == 1:
            if password:
                return f"{match.get('name', '<no name>')} - {match['login'].get('username', '<no username>')} - {match['login'].get('password', '<no password>')}"
            return f"{match.get('name', 'no name')} - {match['login'].get('username', '<no username>')}"
        elif match['type'] == 2:
            return f"{match.get('name', '<no name>')}\n{match['notes'] if match['notes'] else '<no notes content>'}"

    def display_credentials(self, mapping):
        result = []
        for val, match in mapping.items():
            result.append(f"{val}) {self.display_credential(match)}")

        return "\n".join(result)
        
    def select_match(self, matches):
        try:
            return self.select_single_match(matches)
        except ValueError:
            return self.select_from_multiple_matches(matches)
    
    def output_match(self, matches):
        if not matches or len(matches) == 0:
            print("No matches found")
            return
        print(self.select_match(matches)["login"]["password"])

    def confirm_delete(self, matches):
        match = self.select_match(matches)
        print("The following match will be DELETED:")
        print(self.display_credential(match, password=True))
        if input("Confirm? (type 'yes') ").lower() == "yes":
            return match
        print("Cancelled.")
        return False
        
    def unlock(self):
        self.bw.try_get_session()

        while not bw.unlocked:
            email = None
            if bw.needs_email():
                email = input("Email: ")

            pswd = getpass.getpass('Password: ')

            bw.unlock(email, pswd)
            
    def run_get(self, args):
        if args.username:
            match = self.query.get_password(args.service, args.username)
        else:
            match = self.query.search(args.service)
        return match
    
    def command_get(self, args):
        match = self.run_get(args)
        self.output_match(match)
        
    def command_rm(self, args):
        match = self.run_get(args)
        confirmed = ui.confirm_delete(match)
        if bool(confirmed):
            self.query.real_delete_credential(confirmed)
            print("Deleted.")
            
    def command_add(self, args):
        args.username = None
        args.password = None
        args.notes = None
        args.url = None
        args.secureNote = None

        args.name = input("Name: ")
        if args.type == 'note':
            print("Enter note (Ctrl+D to end):")
            args.notes = sys.stdin.read()
        elif args.type == 'pass':
            args.url = input("URL: ")
            args.username = input("Username: ")
            pass1 = getpass.getpass("Password: ")
            pass2 = getpass.getpass("Password (retype)")
            while pass1 != pass2:
                print("Passwords don't match! Try again:")
                pass1 = getpass.getpass("Password: ")
                pass2 = getpass.getpass("Password (retype)")
            
        self.query.add(args)


VERBS = ['get', 'set', 'del']
if __name__ == '__main__':
    from argparse import ArgumentParser
    
    bw = api.Wrapper()
    ui = UI(bw)

    # Instantiate the parser
    parser = ArgumentParser(description='Bitwarden simple python CLI')
    subparsers = parser.add_subparsers(help='sub-command help')

    # Required positional argument
    parser_get = subparsers.add_parser('get', help='Get a password', aliases=['g', 'ge'])
    parser_get.add_argument('service', type=str, help='Service name')
    parser_get.add_argument('username', type=str, nargs='?', help='The username')
    parser_get.set_defaults(func=ui.command_get)

    parser_rm = subparsers.add_parser('rm', help='Delete a password', aliases=['r', 'd', 'de', 'del'])
    parser_rm.add_argument('service', type=str, help='Service name')
    parser_rm.add_argument('username', type=str, nargs='?', help='The username')
    parser_rm.set_defaults(func=ui.command_rm)
    
    parser_add = subparsers.add_parser('add', help='Add an item', aliases=['ad', 'a', 'n', 'ne', 'new'])
    parser_add.add_argument('type', type=str, choices=['pass', 'note'])
    parser_add.set_defaults(func=ui.command_add)

    args = parser.parse_args()
    ui.unlock()
    args.func(args)

    print(bw.extract_logged_user())

    


