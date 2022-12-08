#!/usr/bin/env python3

from __future__ import annotations

import time
import argparse
import subprocess

from typing import Any
from pathlib import Path
from gi import require_version

require_version('Secret', '1')

from gi.repository import Secret

#############################################################
##                  Global variables                       ##
#############################################################
timeout = 10
restricted = ['restricted-qube']

title_length = 18
folder_length = 18
username_length = 18
url_length = None

copy_url = 'Ctrl+U'
copy_password = 'Ctrl+c'
copy_username =  'Ctrl+C'

lockfile = Path.home() / '.qubes-pass.lock'
rofi_options = ['-normal-window', '-dmenu', '-format', 'i']


#############################################################
##                  Argument Layout                        ##
#############################################################
parser = argparse.ArgumentParser(description='''qubes-pass v1.0.0 - A KeePassXC frontend for Qubes''')
parser.add_argument('qube', help='qube to copy the credential to')


#############################################################
##               Functions and Classes                     ##
#############################################################
def lcut(item: str, padding: int) -> str:
    '''
    Pad the item to the specified length with spaces or cut it
    on the padding length.

    Parameters:
        item            the item to lcut

    Returns:
        cutted or padded item
    '''
    if padding is None:
        return item

    if len(item) < padding:
        return item.ljust(padding)

    else:
        return item[:padding - 2] + '..'


def parse_qube_list(qube_list: str) -> list[str]:
    '''
    Parse a list of qube names as it is specified within the KeePass notes

    Parameters:
        qube_list           list in string representation

    Returns:
        parsed list of qube names
    '''
    if qube_list is None:
        return None

    qubes = []

    for item in qube_list.split(','):
        qubes.append(item.strip())

    return qubes


class RofiAbortedException(Exception):
    '''
    Custom exception class.
    '''


class Credential:
    '''
    Represents a credential entry present within KeePass.
    '''

    def __init__(self, item: Secret.Item) -> None:
        '''
        Initialize the Credential object with an Secret.Item object
        obtained via DBus.

        Parameters:
            item            Secret.Item obtained from KeePass

        Returns:
            None
        '''
        self.item = item
        self.attributes = item.get_attributes()

        self.url = self.attributes.get('URL')
        self.uuid = self.attributes.get('Uuid')
        self.path = Path(self.attributes.get('Path'))
        self.title = self.attributes.get('Title')
        self.notes = self.attributes.get('Notes')
        self.username = self.attributes.get('UserName')

        settings = self.parse_settings()

        self.qubes = parse_qube_list(settings.get('qubes'))
        self.timeout = int(settings.get('timeout', timeout))

    def __str__(self) -> str:
        '''
        The string representation of a Credential object is just it's
        list of attributes.

        Parameters:
            None
            
        Returns:
            default dictionary output of the Credential attributes
        '''
        return str(self.attributes)

    def __eq__(self, other: Any) -> bool:
        '''
        Two Credential entries are equal, if their Uuid matches.

        Parameters:
            other           object to compare with

        Returns:
            true if Credentials are equal, false otherwise
        '''
        if type(self) != type(other):
            return False

        return self.uuid == other.uuid

    def parse_settings(self) -> dict():
        '''
        Parses the Notes section of the credential for Qubes specific
        settings and returns them as a dict.

        Parameters:
            None

        Returns:
            settings dictionary
        '''
        settings = {}
        lines = self.notes.split('\n')

        if lines[0].lower() != '[QubesKeepass]':
            return dict()

        for line in lines[1:]:
            
            try:
                setting, value = line.split('=', 1)

                setting = setting.strip()
                value = value.strip()

                settings[setting] = value

            except ValueError:
                break

        return settings

    def get_secret(self) -> str:
        '''
        Obtain the secret for the credential.

        Parameters:
            None

        Returns:
            secret for the credential
        '''
        if self.item.locked:
            self.item.service.unlock_sync([self.item])

        self.item.load_secret_sync()
        return self.item.get_secret().get_text()

    def copy_to_qube(self, attribute: int, qube: str) -> None:
        '''
        Copy the specified attribute to the specified qube. If the credential
        has a dedicated qube assigned, the operation might fail when a different
        qube is selected.

        After the requested attribute was copied, the function sleeps for the
        timeout value specified within the credential. If no other copy operation
        occured within this time, the clipboard of the specified Qube is cleared.

        Parameters:
            attribute       the Credential attribute to copy
            qube            the qube to copy the credential to

        Returns:
            None
        '''
        if self.qubes is not None and qube not in self.qubes:
            print(f'[-] Copy operation blocked. Selected credential is not allowed for {qube}.')
            return

        if self.qubes is None and qube in restricted:
            print(f'[-] Copy operation blocked. {qube} is a restricted qube.')
            return

        value = ''

        if attribute == 0 or attribute == 10:
            print(f'[+] Copying password of credential {self.title} to {qube}.')
            value = self.get_secret().encode()

        elif attribute == 11:
            print(f'[+] Copying username of credential {self.title} to {qube}.')
            value = self.username.encode()

        elif attribute == 12:
            print(f'[+] Copying url of credential {self.title} to {qube}.')
            value = self.url.encode()

        process = subprocess.Popen(['qrexec-client-vm', qube, 'custom.QubesKeepass'], stdin=subprocess.PIPE)
        process.communicate(input=value)

        lockfile.touch()
        timestamp = lockfile.stat().st_mtime

        print(f'[+] Sleeping for {self.timeout} seconds.')

        time.sleep(self.timeout)
        timestamp2 = lockfile.stat().st_mtime

        if timestamp != timestamp2:
            print('[+] Another copy operation occured. Not cleaning the clipboard.')
            return

        else:
            lockfile.unlink()

            process = subprocess.Popen(['qrexec-client-vm', qube, 'custom.QubesKeepass'], stdin=subprocess.PIPE)
            process.communicate(input=''.encode())

            print(f'[+] Clipboard of {qube} cleared.')


class CredentialCollection:
    '''
    Represents a collection of Credential objects.
    '''

    def __init__(self, credentials: list[Credential]) -> None:
        '''
        Initialize a CredentialCollection with a list of credentials.

        Parameters:
            credentials         the credentials to include into the collection

        Returns:
            None
        '''
        self.credentials = sorted(credentials, key=lambda x: x.path.parent)

    def filter_credentials(self, qube: str) -> None:
        '''
        Filter the list of credentials for the specified qube. Filtered
        credentials include all credentials with a matching qube name
        and credentials without qube specification. Restricted qubes can
        only obtain credentials that explicitly target these qubes.

        Parameters:
            qube                 qube to filter for

        Returns:
            None
        '''
        filtered = []

        for cred in self.credentials:

            if cred.qubes is not None and qube in cred.qubes:
                filtered.append(cred)

            elif cred.qubes is None and qube not in restricted:
                filtered.append(cred)

        self.credentials = filtered

    def __str__(self) -> str:
        '''
        The string representiation of a CredentialCollection is a formatted list
        that can be displayed within rogi.

        Parameters:
            credentials         list of credentials to display

        Returns:
            None
        '''
        formatted = ''

        for credential in self.credentials:
            
            folder = credential.path.parent.name or 'Root'

            formatted += lcut(credential.title, title_length)
            formatted += lcut(folder, folder_length)
            formatted += lcut(credential.username, username_length)
            formatted += lcut(credential.url, url_length)
            formatted += '\n'

        return formatted

    def display_rofi(self, qube: str = 'Qube') -> (int, Credential):
        '''
        Displays the contained credentials within rofi and waits for a user
        selection. The selected Credential and the exit value of rofi are
        returned.

        Parameters:
            qube        the qube name to copy the password to

        Returns:
            Credential item selected by the user and exit code
        '''
        rofi_mesg = f'Selected credential is copied to <b>{qube}</b>\n\n'
        rofi_mesg += lcut('Title', title_length)
        rofi_mesg += lcut('Folder', folder_length)
        rofi_mesg += lcut('Username', username_length)
        rofi_mesg += lcut('URL', url_length)

        mappings = ['-kb-custom-1', copy_password]
        mappings += ['-kb-custom-2', copy_username]
        mappings += ['-kb-custom-3', copy_url]

        print('[+] Starting rofi.')
        process = subprocess.Popen(['rofi'] + rofi_options + ['-mesg', rofi_mesg] + mappings,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        try:
            selected = process.communicate(input=str(self).encode())[0]
            selected = int(selected.decode().strip())

        except ValueError:
            raise RofiAbortedException('rofi selection was aborted by user')

        print(f'[+] User selected {self.credentials[selected].title} with return code {process.returncode}')
        return (process.returncode, self.credentials[selected])

    def load(service: Secret.Service) -> CredentialCollection:
        '''
        Load credential information via DBus and create a new CredentialCollection
        from it.

        Parameters:
            service         DBus connection to the Secret Service

        Returns:
            None
        '''
        credentials = []
        collection = Secret.Collection.for_alias_sync(service, "default", Secret.CollectionCreateFlags.NONE, None)

        for item in collection.get_items():
            credential = Credential(item)
            credentials.append(credential)

        return CredentialCollection(credentials)


#############################################################
##                     Main Method                         ##
#############################################################
def main() -> None:
    '''
    Main function. Ask the user for a credential to copy and copy it into
    the specified Qube.

    Parameters:
        None

    Returns:
        None
    '''
    args = parser.parse_args()

    try:
        service = Secret.Service.get_sync(Secret.ServiceFlags.OPEN_SESSION | Secret.ServiceFlags.LOAD_COLLECTIONS)

    except Exception as e:
        print('[-] Unable to get Secret Service connection.')
        print('[-] Error Message: ' + str(e))

    collection = CredentialCollection.load(service)
    collection.filter_credentials(args.qube)

    try:
        attr, credential = collection.display_rofi(args.qube)
        credential.copy_to_qube(attr, args.qube)

    except RofiAbortedException:
        print('[+] Aborted.')


main()
