# Heavily based on https://github.com/malice-plugins/pescan/blob/master/malice/__init__.py#L40

from os import path
import pefile
import subprocess

class PeResults(object):

    def __init__(self, file_path):
        self.file = file_path
        self.results = {}
        self.result_sections = None
        if not path.exists(self.file):
            raise Exception("file does not exist: {}".format(self.file))

    def imports(self, pef):
        imports = []
        if hasattr(pef, 'DIRECTORY_ENTRY_IMPORT') and len(pef.DIRECTORY_ENTRY_IMPORT) > 0:
            for entry in pef.DIRECTORY_ENTRY_IMPORT:
                try:
                    if isinstance(entry.dll, bytes):
                        dll = entry.dll.decode()
                    else:
                        dll = entry.dll
                    dlls = {dll: []}
                    for symbol in entry.imports:
                        if isinstance(symbol.name, bytes):
                            name = symbol.name.decode()
                        else:
                            name = symbol.name
                        dlls[dll].append(dict(address=hex(symbol.address), name=name))
                    imports.append(dlls)
                except Exception:
                    continue
        self.results['imports'] = imports

    def strings(self):
        # run the `strings -e l ` command on the file
        strings = subprocess.check_output(["strings", "-e", "l", self.file])
        self.results['strings'] = strings.decode().split('\n')

    def run_analysis(self):
        try:
            self.strings()
            pef = pefile.PE(self.file)
            self.imports(pef)
            self.results['imphash'] = pef.get_imphash()
        except Exception as e:
            print("[E] Unable to parse PE file: {0}".format(e))
        
        return self.results