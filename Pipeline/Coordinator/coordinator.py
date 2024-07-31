import os
import logging
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename, import_string
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime
import hashlib
import json
import shutil
import re
import csv
from peresults import PeResults
import struct
import base64
import random

## Configurations
ELEMENTS_PER_PAGE = 50

# Persistent storage
STORAGE_FOLDER = "/storage/files"

# Temporary storage
UPLOAD_FOLDER = "/storage/uploads"

app = Flask(__name__)
CORS(app)
# 350 MB max upload size, everything else will be too much after some time...
app.config['MAX_CONTENT_LENGTH'] = 350 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

health_status = True

from models import *
#database_file = f"sqlite:///{DB_FILE}"
database_file = f"postgresql://pipeline:POSTGRES_PASSWORD@coordinator-db/pipeline"
app.config["SQLALCHEMY_DATABASE_URI"] = database_file
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
#app.config["SQLALCHEMY_ECHO"] = True
db.init_app(app)

# To handle transactions more smoothly
from contextlib import contextmanager
@contextmanager
def transaction(raiseExc=False):
    try:
        yield
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        if raiseExc:
            raise
        else:
            app.logger.error(str(e))

def model_to_dict(obj):
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns if c.name not in ['architecture', 'tag']}

def reload_db_obj(what):
    db.session.flush()
    db.session.refresh(what)


@app.route('/notes-filter/<title>')
def notes_by(title):
    """Returns all notes with the given title"""
    try:
        return {'notes': [{
            'title': n.title,
            'content': n.content,
            'isfor': n.isfor,
            'created_at': n.created_at,
            'id': n.id
        } for n in db.session.query(Notes).filter(Notes.title==title)]}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/notes')
def notes():
    """Returns all notes"""
    try:
        return {'notes': [{
            'title': n.title,
            'content': n.content,
            'isfor': n.isfor,
            'created_at': n.created_at,
            'id': n.id
        } for n in db.session.query(Notes).all()]}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/notes/<int:file_id>')
def notes_for(file_id):
    """Returns all notes that are related to a specific file."""
    return {'notes': [{
            'title': n.title,
            'content': json.loads(n.content),
            'isfor': n.isfor,
            'created_at': n.created_at,
            'id': n.id
        } for n in Notes.query.filter_by(isfor=file_id).all()]}

@app.route('/fuzzing-notes/<int:driver_id>/<log_type>', methods=['POST'])
def fuzzing_notes(driver_id, log_type):
    """Receives fuzzing logs for drivers and saves them to the correct notes."""
    driver = db.session.query(Drivers).filter_by(id=driver_id).first()
    if driver is None:
        return {'error': 'Driver not found'}, 404
    try:
        with transaction(raiseExc=True):
            note = Notes(title=log_type, content=request.data.decode('utf-8'), isfor=driver.file, created_at=datetime.now())
            db.session.add(note)
        #app.logger.info(f"Received fuzzing log for driver {driver_id} of type {log_type}: {request.data}")
    except Exception as e:
        return {'error': str(e)}, 500
    
    return {'success': True}, 200

def identification_notes_for(file_id):
    return {'notes': [{
            'title': n.title,
            'content': json.loads(n.content),
            'isfor': n.isfor,
            'created_at': n.created_at,
            'id': n.id
        } for n in Notes.query.filter_by(isfor=file_id).all() if n.title in ['trid', 'exiftool', 'magic']]}

@app.route('/identification-notes/<int:file_id>')
def identification_notes(file_id):
    """Returns all notes that are related to identification for a specific file."""
    try:
        return identification_notes_for(file_id), 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/files-info/<limit>')
def files_info(limit):
    """Get all files information (i.e. IDs)."""
    try:
        return {'files': [model_to_dict(f) for f in db.session.query(Files).limit(limit).all()]}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/existing-files-info/<int:page>')
def existing_files_info(page=1):
    """Get all files that do exist on disc, with their identification notes, by pagination."""
    # TODO make more efficient somehow by saving those already done...
    pages = db.session.query(Files)\
        .filter((Files.ssdeep.is_not(None)) & (Files.path.is_not(None)))\
        .order_by(Files.id.desc())\
        .paginate(page=page,per_page=ELEMENTS_PER_PAGE,error_out=False)
        #.select_entity_from(Drivers).join(Files, isouter=True)\
    
    files = []
    for f in pages.items:
        file = model_to_dict(f)
        # add the identification notes
        file['notes'] = identification_notes_for(f.id)['notes']
        files.append(file)
    return {'files': files}, 200

@app.route('/unidentified-files-info')
def unidentified_files_info():
    """Get all files that have not been identified yet."""
    files = db.session.query(Files)\
        .filter((Files.ssdeep.is_(None)) & (Files.path.is_not(None)))\
        .order_by(Files.id.asc())\
        .all()
    return {'files': [model_to_dict(f) for f in files]}, 200

@app.route('/windows-executables/<int:page>')
def windows_executables(page=1):
    """Get all files that are identified as Windows executables, by pagination."""
    # if a file has an architecture it is identified as a Windows executable
    pages = db.session.query(Files)\
        .filter((Files.architecture.is_not(None)) & (Files.path.is_not(None)) & (Files.ssdeep.is_not(None)))\
        .order_by(Files.id.desc())\
        .paginate(page=page,per_page=ELEMENTS_PER_PAGE,error_out=False)

    files = []
    for f in pages.items:
        file = model_to_dict(f)
        files.append(file)
    return {'files': files}, 200

def is_windows_executable(file, file_info):
    driver_probable_counter = 0

    #???% (.EXE) Win64 Executable (generic) (10523/12/4)
    #???% (.EXE) Win16 NE executable (generic)
    #???% (.EXE) OS/2 Executable (generic) (2029/13)
    # and many more
    regex_exec = r"(\d{1,3}\.\d{1,2})% \(\.EXE\) (Win64|Win16\ NE|OS\/2|DOS|Generic Win\/DOS) (E|e)xecutable .*"
    matches = re.finditer(regex_exec, '\n'.join(file_info['trid']), re.MULTILINE)
    for mat in matches:
        precent = float(mat.group(1))
        driver_probable_counter += precent / 100

    # PE32+ executable (native)
    # PE32 executable (DLL) (native)
    matches = re.finditer(r"(PE32\+?) executable \(?.*\)? ?\(native\)", file_info['magic']['description'], re.MULTILINE)
    if next(matches, None) is not None:
        driver_probable_counter += 0.5

    # if the original filename or internal name contains .sys, it is likely a driver
    if 'OriginalFileName' in file_info['exiftool'] and ".sys" in file_info['exiftool']['OriginalFileName']:
        driver_probable_counter += 0.5
    elif 'InternalName' in file_info['exiftool'] and ".sys" in file_info['exiftool']['InternalName']:
        driver_probable_counter += 0.5
    elif ".sys" in file.filename:
        driver_probable_counter += 0.5
    
    # MachineType is required for both IDA & Fuzzing, so if it is not present, it cannot count as an executable
    if 'MachineType' not in file_info['exiftool'] or file_info['exiftool']['MachineType'] is None:
        driver_probable_counter -= 1
    return driver_probable_counter > 0

def map_exiftool_architecture(machine_type):
    if machine_type is None:
        return None
    if "AMD AMD64" in machine_type:
        return "AMD64"
    if "Intel 386" in machine_type:
        return "AMD32"
    # Not sure if these are correct, see
    # https://raw.githubusercontent.com/php/php-src/master/ext/fileinfo/tests/magic
    if "Unknown (0xaa64)" in machine_type:
        return "ARM64"
    if "Unknown (0x1c2)" in machine_type:
        return "ARM16"
    if "Unknown (0x1c4)" in machine_type:
        return "ARM16"
    if "Unknown (0x01c0)" in machine_type:
        return "ARM32"
    
    # Intel IA-64 is in theory discontinued?
    if "Intel IA64" in machine_type:
        return "IA64"
    return None

def clean_filename(filename):
    # remove all things that might break pathing after download
    return filename.replace("/", "_").replace("\\", "_").replace(":", "_")\
                .replace(" ", "_").replace('"', "_").replace("'", "_")\
                .replace("?", "_").replace("*", "_").replace("<", "_")\
                .replace(">", "_").replace("|", "_")

def extract_static_results(bin_strings):
    dosdevice = None
    security_str = None
    has_physmem_str = False
    # from https://github.com/RobThree/HttpNamespaceManager/blob/master/HttpNamespaceManagerLib/AccessControl/SecurityDescriptor.cs
    sddlReg = r"^(O:([A-Z]+?|S(-[0-9]+)+)?)?(G:([A-Z]+?|S(-[0-9]+)+)?)?(D:([A-Z]*(\([^\)]*\))*))?(S:([A-Z]*(\([^\)]*\))*))?$"
    dos_device_access_strings = set()
    other_device_access_strings = set()
    security_strings = set()
    for s in bin_strings:
        if "PhysicalMemory" in s:
            has_physmem_str = True
        if "\\DosDevices" in s:
            # there should only be one at most? --> nope sometimes multiples
            dos_device_access_strings.add(s)
        if "\\??\\" in s or "\\Global??\\".lower() in s.lower():
            # In theory also \\\\Global?? but much less common
            other_device_access_strings.add(s)

        if re.match(sddlReg, s.strip()) is not None:
           security_strings.add(s.strip())
    
    dos_device_access_strings = [s for s in dos_device_access_strings if len(s) > 0]
    other_device_access_strings = [s for s in other_device_access_strings if len(s) > 0]
    security_strings = [s for s in security_strings if len(s) > 0]

    # Combine them to save in DB
    if len(dos_device_access_strings) > 0:
        dosdevice = ','.join(dos_device_access_strings)
    if len(other_device_access_strings) > 0:
        if dosdevice is None:
            dosdevice = ','.join(other_device_access_strings)
        else:
            dosdevice += ',' + ','.join(other_device_access_strings)
    
    if len(security_strings) > 0:
        security_str = '|'.join(security_strings)

    return has_physmem_str, dosdevice, security_str

def appendFunctionsStaticResults(func_names, static_result: StaticResults):
    for func_name in func_names:
        function = Functions.query.filter_by(name=func_name).first()
        if function is None:
            function = Functions(name=func_name)
            db.session.add(function)
        reload_db_obj(function)
        static_result.imports.append(function)

@app.route('/files/<int:file_id>', methods=['POST'])
def file_identification_results(file_id):
    """Update the specified file identification."""
    try:
        file_info = request.json
        with transaction():
            file = db.session.get(Files, file_id)
            if file is None:
                return {'error': 'File not found'}, 404
            if file_info['ssdeep'] is None:
                return {'error': 'ssdeep cannot be None for identification update!'}, 400
            file.ssdeep = file_info['ssdeep']

            # add note with all of the exif data
            if file_info['exiftool'] is not None:
                note = Notes(title="exiftool", content=json.dumps(file_info['exiftool']), isfor=file.id, created_at=datetime.now())
                db.session.add(note)

                # Update the filename if the OriginalFileName is present
                # and if the filename is either empty or a hash
                if 'OriginalFileName' in file_info['exiftool']:
                    poss_new_filename = file_info['exiftool']['OriginalFileName']
                    poss_new_filename = clean_filename(poss_new_filename)
                    if len(poss_new_filename) > 0 and poss_new_filename not in [".sys"]: # some drivers have weird names, lets block those straight up
                        file.filename = poss_new_filename
            else:
                raise Exception(f"File {file_id} without exiftool in identification?")

            # add note with all of the trid data
            if file_info['trid'] is not None:
                note = Notes(title="trid", content=json.dumps(file_info['trid']), isfor=file.id, created_at=datetime.now())
                db.session.add(note)
            else:
                raise Exception(f"File {file_id} without trid in identification?")

            # update all possible ogFiles with the new type
            if file_info['magic'] is not None:
                for ogf in db.session.query(OgFiles).filter_by(file=file.id).all():
                    ogf.type = file_info['magic']['description']
                # and add the magic note
                note = Notes(title="magic", content=json.dumps(file_info['magic']), isfor=file.id, created_at=datetime.now())
                db.session.add(note)
            else:
                app.logger.error(f"File {file_id} without magic in identification?")

            # check if this file is a known vulnerable driver
            known_vuln = db.session.query(KnownVulnerableDrivers).filter_by(sha256=file.sha256.lower()).first()
            if known_vuln is not None:
                # only if the sha256 matches, set the underlying file for a driver
                known_vuln.file = file.id
            else:
                # otherwise still check if it might be one based on the internal filename on the signature
                spl = file.filename.split(".")
                if len(spl) != 2 or spl[1].lower() != "sys":
                    #app.logger.info(f"File {file_id} with invalid/non-sys filename to check for vuln purely based on filename?: {file.filename}")
                    pass
                elif len(spl[0]) < 3:
                    #app.logger.info(f"File {file_id} with too short filename to check for vuln purely based on filename?: {file.filename}")
                    pass
                else:
                    # This check for known vulnerable is fine to have false positives, better that than to miss some
                    known_vuln = db.session.query(KnownVulnerableDrivers).filter(KnownVulnerableDrivers.filename.like(f"{spl[0]}%")).first()
                    if known_vuln is not None:
                        app.logger.info(f"File {file_id} identified as known vulnerable purely by filename: {file.filename}")

            # Check the given information, if this is an executable
            # run the static analysis and make it a driver if it is
            if is_windows_executable(file, file_info):
                arch = map_exiftool_architecture(file_info['exiftool']['MachineType'])
                if arch is None:
                    app.logger.error(f"File {file_id} without architecture in identification?")
                file.architecture = arch

                pe_results = PeResults(file.path).run_analysis()
                # add the strings result as a note
                if 'strings' in pe_results['strings']:
                    note = Notes(title="strings", content=json.dumps(pe_results['strings']), isfor=file.id, created_at=datetime.now())
                    db.session.add(note)
                
                # add the imports as a note
                if 'imports' in pe_results:
                    note = Notes(title="imports", content=json.dumps(pe_results['imports']), isfor=file.id, created_at=datetime.now())
                    db.session.add(note)
                
                # Is it a driver?
                imports = []
                kernel_driver_imports = ['ntoskrnl.exe', 'wdfldr.sys']
                for imp in pe_results['imports']:
                    for imp_key in imp.keys():
                        if imp_key.lower() in kernel_driver_imports:
                            imports += imp[imp_key]
                    # WDF libary functions cannot be gotten from imports
                    # will be a result from the IDA executions where possible
                
                if len(imports) > 0 or file.filename.lower().endswith(".sys"):
                    app.logger.info(f"File {file.filename} ({file.id}) is probably an {file.architecture} driver!")
                    # add the static result
                    imphash = pe_results['imphash'] if pe_results['imphash'] else None
                    static_result = None
                    if pe_results['strings'] is None:
                        static_result = StaticResults(imphash=imphash, created_at=datetime.now())
                    else:    
                        has_physmem_str, dosdevice, security_str = extract_static_results(pe_results['strings'])
                        static_result = StaticResults(phys_mem=has_physmem_str, concat_dos_device_str=dosdevice, security_str=security_str, imphash=imphash, created_at=datetime.now())
                    db.session.add(static_result)
                    reload_db_obj(static_result)

                    # add all import functions (WDF has more, but requires IDA to get them all)
                    appendFunctionsStaticResults([func['name'] for func in imports], static_result)

                    tag = "unknown" if known_vuln is None else "known_vulnerable"
                    driver = Drivers(file=file.id, tag=tag, static_results=static_result.id, created_at=datetime.now())
                    db.session.add(driver)
                else:
                    app.logger.info(f"File {file.filename} ({file.id}) is an executable, but most likely not a driver.")
            elif known_vuln is not None:
                app.logger.error(f"File {file.filename} ({file.id}) is a known vulnerable driver, but not recognized as a driver!!!")
            else:
                app.logger.info(f"File {file.filename} ({file.id}) is not an executable.")

        return {'success': True}, 200
    except Exception as e:
        app.logger.error(str(e))
        return {'error': str(e)}, 500

@app.route('/files/<int:file_id>', methods=['DELETE'])
def file_delete(file_id):
    """Delete the specified file from disk."""
    try:
        with transaction():
            file = db.session.get(Files, file_id)
            if file is None:
                return {'error': 'File not found'}, 404
            if file.path is None: # equivalent to file does not exist
                return {'success': True}, 200
            # if the file is a driver, do not delete it
            if db.session.query(Drivers).filter_by(file=file_id).first() is not None:
                return {'error': 'Cannot delete a driver file'}, 400
            os.remove(file.path)
            file.path = None
            # file.size = 0 # lets keep original size around
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/files/<int:file_id>', methods=['PUT'])
def file_update(file_id):
    """Update the specified file with the given information."""
    try:
        file_info = request.json
        with transaction():
            file = db.session.get(Files, file_id)
            if file is None:
                return {'error': 'File not found'}, 404
            if 'filename' in file_info:
                file.filename = clean_filename(file_info['filename'])
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/files/<int:file_id>', methods=['GET'])
def file(file_id):
    """Get a file by its id."""
    try:
        file = db.session.get(Files, file_id)
        if file is None:
            return {'error': 'File not found'}, 404
        if file.path is None:
            app.logger.error(f"File {file_id} without filepath?")
            return {'error': 'File without filepath???'}, 404
        return send_file(os.path.join(STORAGE_FOLDER, file.sha256), download_name=file.filename, as_attachment=True)
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/file-id/<file_hash>', methods=['GET'])
def file_id_by(file_hash):
    """Returns the file ID for the given SHA1 or SHA256 hash."""
    try:
        if len(file_hash) == 40:
            # SHA1
            file = db.session.query(Files).filter(Files.sha1==file_hash.lower()).first()
        elif len(file_hash) == 64:
            # SHA256
            file = db.session.query(Files).filter(Files.sha256==file_hash.lower()).first()
        else:
            return {'error': 'Invalid hash length'}, 400
        if file is None:
            return {'error': 'File not found'}, 404
        return {'file': file.id}, 200
    except Exception as e:
       return {'error': str(e)}, 500

def add_new_origin(sha256, origin):
    with transaction():
        file = db.session.query(Files).filter_by(sha256=sha256).first()
        if file is None:
            app.logger.error(f"File {sha256} not found in the database?")
            return {'error': 'File not found in the database, but IntegrityError?'}, 404
        #first check if the same og_file already exists
        old_og = db.session.query(OgFiles).filter_by(file=file.id, origin=origin).first()
        if old_og is not None:
            return {'error': 'OgFiles already exists', 'ogfile_id': old_og.id}, 409
        # add a second ogfile with the same file
        og = OgFiles(file=file.id, origin=origin,
                     created_at=datetime.now(), extracted=False)
        db.session.add(og)
        reload_db_obj(og)
        return {'success': True, 'ogfile_id': og.id}, 200

@app.route('/ogfile/<file_hash>', methods=['GET'])
def get_ogfile_by(file_hash):
    """Get the origin file info in addition to the underlyin file ID."""
    try:
        if len(file_hash) == 64: # SHA256
            file = db.session.query(Files).filter(Files.sha256==file_hash).first()
        else:
            return {'error': 'Invalid hash length'}, 400
        if file is None:
            return {'error': 'File not found'}, 404
        return {'success': True, 'file': file.id, 
                'ogfiles': [model_to_dict(ogf) for ogf in db.session.query(OgFiles).filter_by(file=file.id).all()]}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/ogfile/<file_hash>', methods=['POST'])
def add_ogfile_by(file_hash):
    """Adds another origin file for this file."""
    try:
        if len(file_hash) == 64: # SHA256
            file = db.session.query(Files).filter(Files.sha256==file_hash).first()
        else:
            return {'error': 'Invalid hash length'}, 400
        if file is None:
            return {'error': 'File not found'}, 404
        
        origin = request.form.get('origin', None)
        if origin is None:
            return {'error': 'No origin provided'}, 400
        
        return add_new_origin(file_hash, origin)
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/ogfile/<ogfile_id>', methods=['PATCH'])
def update_ogfile(ogfile_id):
    """Updates the extracted status of an ogfile."""
    try:
        with transaction():
            ogf = db.session.query(OgFiles).filter_by(id=ogfile_id).first()
            if ogf is None:
                return {'error': 'OgFiles not found'}, 404
            ogf.extracted = True
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

def calculate_sha_hashes(full_path):
    with open(full_path, 'rb') as f:
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        while True:
            data = f.read(65536) # lets read stuff in 64kb chunks!
            if not data:
                break
            sha256.update(data)
            sha1.update(data)
    return sha1.hexdigest(), sha256.hexdigest()

@app.route('/ogfile', methods=['POST'])
def add_ogfile():
    """Add an ogfile to the database, including the actual file."""
    try:
        try:
            actual_file = request.files['file']
        except RequestEntityTooLarge as e:
            return {'error': 'File too large'}, 413
        
        if actual_file:
            filename = clean_filename(secure_filename(actual_file.filename))
            full_path_upload = os.path.join(UPLOAD_FOLDER, filename)
            actual_file.save(full_path_upload)
            
            size = os.stat(full_path_upload).st_size
            sha1, sha256 = calculate_sha_hashes(full_path_upload)

            origin = request.form.get('origin', None)
            if origin is None:
                return {'error': 'No origin provided'}, 400
            
            try:            
                with transaction(raiseExc=True):
                    dest = os.path.join(STORAGE_FOLDER, sha256)
                    file = Files(path=dest, filename=filename, size=size, sha256=sha256, sha1=sha1)
                    db.session.add(file)
                    reload_db_obj(file)
                    # if adding the file was successful, move it to the actual location
                    shutil.move(full_path_upload, dest)
                    # then add the ogfile
                    og = OgFiles(file=file.id, origin=origin, created_at=datetime.now())
                    db.session.add(og)
                    reload_db_obj(og)
                    return {'success': True, 'ogfile_id': og.id}, 200
            except IntegrityError as e:
                # Update the OgFiles with the new? origin
                return add_new_origin(sha256, origin)
        else:
            return {'error': 'No file provided'}, 400
    except Exception as e:
        # delete the file if it was saved
        if actual_file:
            try:
                os.remove(full_path_upload) # TODO remove also if not actual_file
            except Exception as e:
                app.logger.error("Could not delete file %s" % full_path_upload, exc_info=True)
        return {'error': str(e)}, 500

@app.route('/ogfile', methods=['GET'])
def add_ogfile_form():
    """Return a form to add an ogfile manually."""
    return '''
    <!doctype html>
    <title>Add OGFile</title>
    <h1>Add OGFile</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=text name=origin>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/ogfiles-to-extract/<type>/<int:page>', methods=['GET'])
def ogfiles_to_extract(type=None, page=1):
    """Get all ogfiles that need to be extracted, by pagination."""
    if type is None:
        return {'error': 'No type provided'}, 400
    # get all OgFiles where the type is like the given type
    pages = db.session.query(OgFiles)\
        .filter(OgFiles.extracted==False)\
        .filter(OgFiles.type.like(f"%{type}%"))\
        .order_by(OgFiles.id.desc())\
        .paginate(page=page,per_page=ELEMENTS_PER_PAGE,error_out=False)
    return {'ogfiles': [model_to_dict(ogf) for ogf in pages.items]}, 200

@app.route('/ogfiles-info')
def ogfiles_info():
    """Get all ogfiles information (i.e. IDs)."""
    try:
        return {'ogfiles': [model_to_dict(ogf) for ogf in db.session.query(OgFiles).all()]}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/ogfiles/<int:ogfile_id>', methods=['GET'])
def ogfile(ogfile_id):
    """Get an ogfile by its id."""
    try:
        ogf = db.session.query(OgFiles).filter_by(file=ogfile_id).first()
        if ogf is None:
            return {'error': 'OgFiles not found'}, 404
        return {'ogfile': model_to_dict(ogf)}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/ogfiles-filter/origin/<origin>', methods=['GET'])
def ogfiles_by_origin(origin):
    """Get all ogfiles with the given origin."""
    try:
        ogfiles = [model_to_dict(ogf) for ogf in db.session.query(OgFiles).filter(OgFiles.origin.like(f"%{origin}%")).all()]
        return {'ogfiles': ogfiles}, 200
    except Exception as e:
       return {'error': str(e)}, 500
    
@app.route('/origins', methods=['GET'])
def origins():
    """Get all origins."""
    try:
        return {'origins': [row.org for row in db.session.query(OgFiles.origin.distinct().label("org")).all()]}, 200
    except Exception as e:
       return {'error': str(e)}, 500

def create_queue_result(fuzzQueueElem):
    return {
        'running': [model_to_dict(f) for f in fuzzQueueElem if f.state == FuzzState.running],
        'queued': [model_to_dict(f) for f in fuzzQueueElem if f.state == FuzzState.queued],
        'done': [model_to_dict(f) for f in fuzzQueueElem if f.state == FuzzState.done],
        'errored': [model_to_dict(f) for f in fuzzQueueElem if f.state == FuzzState.errored],
    }

@app.route('/fuzzing-queue/<int:driver_id>', methods=['GET'])
def fuzzing_queue_for(driver_id):
    """Get the fuzzing queue for a specific driver."""
    try:
        fuzzQueueElem = db.session.query(FuzzQueue).filter_by(driver=driver_id).all()
        return create_queue_result(fuzzQueueElem), 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/fuzzing-queue', methods=['GET'])
def fuzzing_queue():
    """Get the fuzzing queue."""
    try:
        fuzzQueueElem = db.session.query(FuzzQueue).all()
        return create_queue_result(fuzzQueueElem), 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/fuzzing-queue', methods=['DELETE'])
def fuzzing_queue_clear():
    """Clear the fuzzing queue."""
    return {'error': 'Was just for testing!'}, 400
    try:
        with transaction():
            db.session.query(FuzzQueue).filter(FuzzQueue.state==FuzzState.queued).delete()
        return {'success': True}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/fuzzing-queue-add-interesting', methods=['GET'])
def add_interesting_fuzzing_to_queue():
    """Add all unknown drivers that are "interesting" to the fuzzing queue."""
    app.logger.info("Adding interesting drivers to the fuzzing queue...")
    query = db.session.query(Drivers, PathResults)\
        .outerjoin(Files, Drivers.file==Files.id)\
        .join(StaticResults, Drivers.static_results==StaticResults.id)\
        .join(PathResults, Drivers.path_results==PathResults.id)\
        .filter(PathResults.ret_code>=100, StaticResults.concat_dos_device_str!="")
    # none that are marked as known vulnerable, poced, not vulnerable or vulnerable
    # all those that have a ret_code > 100
    # all that have a physical string, regardless of concat_dos_device_str - low prio
    # cannot have a fuzzing queue entry already
    added = 0
    for driver, path_res in query.all():
        if driver.tag in [Tags.known_vulnerable, Tags.not_vulnerable, Tags.vulnerable, Tags.poced]:
            continue
        if path_res.ret_code < 100:
            continue
        if db.session.query(FuzzQueue).filter_by(driver=driver.id).first() is not None:
            continue
        if possibly_fuzz(driver, path_res, path_res.ret_code):
            added += 1
    app.logger.info("Done adding!")
    return {'success': True, 'added': added}, 200

def create_ioctl_seeds_for(driver_id, driver=None):
    if driver is None and driver_id is None:
        app.logger.error("No driver provided for which to create the seeds!")
        return []
    if driver is None:
        driver = db.session.query(Drivers).filter_by(id=driver_id).first()
        if driver is None:
            app.logger.error(f"Driver {driver_id} not found for which to create the seeds!")
            return []
    
    # get the pathResults ioctl_comp
    path_res = db.session.query(PathResults).filter_by(id=driver.path_results).first()
    if path_res is None:
        app.logger.error(f"Driver {driver_id} has no pathResults to create the seeds!")
        return []

    try:
        ioctl_comp = json.loads(path_res.ioctl_comp)
    except Exception as e:
        app.logger.error(f"Driver {driver_id} has invalid ioctl_comp to create the seeds: {e}")
        return []
    
    ioctl_set = set()
    for ioctl in ioctl_comp:
        if "=" in ioctl['op']:
            ioctl_set.add(ioctl['val'])
        # should get us into both branches
        if "<" in ioctl['op']:
            ioctl_set.add(ioctl['val'] - 0x4)
            ioctl_set.add(ioctl['val'])
        if ">" in ioctl['op']:
            ioctl_set.add(ioctl['val'] + 0x4)
            ioctl_set.add(ioctl['val'])
    
    app.logger.info(f"Driver {driver_id} has {len(ioctl_set)} unique ioctls to create seeds for.")
    
    # create the seeds
    def cyclic(length, n=4):
        pattern = b''
        sequence = b''
        count = 0

        while count < length:
            if len(sequence) == n:
                pattern += sequence
                sequence = b''
            sequence += struct.pack('<h', count)
            count += 1
        
        return pattern

    def seed(ioctl, inputSize, outputSize, empty):
        # <: This indicates that the data should be packed using little-endian byte order.
        #    Little-endian means the least significant byte is stored first. 
        # I: This specifies an unsigned integer (int) which is 4 bytes (32 bits) long.
        # h: This specifies a signed short (short int) which is 2 bytes (16 bits) long. The h appears twice, meaning two signed shorts are expected.
        data = struct.pack('<Ihh', ioctl, inputSize, 0x1000)
        total_size = inputSize + outputSize
        data += b'\x00' * total_size if empty else cyclic(total_size)[:total_size]
        return base64.b64encode(data).decode()

    seed_obj = []
    for ioctl in ioctl_set:
        with transaction():
            # different input sizes found in drivers, the sum is total size, fuzzer will adjust them
            seeds = [
                #seed(ioctl, inputSize=8, outputSize=8, empty=True),
                seed(ioctl, inputSize=16, outputSize=16, empty=True),
                #seed(ioctl, inputSize=0x80, outputSize=0x80, empty=True),
                seed(ioctl, inputSize=0x80, outputSize=0x80, empty=False),
                seed(ioctl, inputSize=0x1000, outputSize=0x1000, empty=True),
                #seed(ioctl, inputSize=0x1000, outputSize=0x1000, empty=False),
            ]

            for s in seeds:
                fuzz = FuzzPayload(version="0.1", ioctl=hex(ioctl), payload=s, type="seed", created_at=datetime.now())
                db.session.add(fuzz)
                reload_db_obj(fuzz)
                seed_obj.append(fuzz)

    return seed_obj

def fuzzing_queue_add_internal(driver_id, priority, seeds, dos_device_str, max_runtime=60*60*12, max_last_crash=60*60*8, max_last_any=60*60*4):
    # remove the text before the actual name the driver has to use
    # i.e. from \\DosDevices\xxx to xxx, \\??\C:\test.sys to C:\test.sys
    if 'DosDevices' in dos_device_str:
        dos_device_str = dos_device_str.split('\\')[-1]
    elif '\\??\\' in dos_device_str:
        dos_device_str = dos_device_str[4:]
    else:
        return {'error': f'Invalid dos_device_str: {dos_device_str}'}, 400
    
    if len(dos_device_str) == 0:
        return {'error': 'After parsing the dos device string was empty!'}, 400

    with transaction():
        fuzz = FuzzQueue(driver=driver_id, priority=priority,\
                        dos_device_str=dos_device_str, state=FuzzState.queued, \
                        max_runtime=max_runtime, max_last_crash=max_last_crash, \
                        max_last_any=max_last_any, created_at=datetime.now())
        for seed in seeds:
            fuzz.seeds.append(seed)
        db.session.add(fuzz)
    
    return {'success': True}, 200

def possibly_fuzz(driver, path_res, prio):
    if driver.tag == Tags.unknown and path_res.ioctl_comp is not None and len(path_res.ioctl_comp) > 7:
        # get the first of the concat_dos_device_str from the static results
        static_res = db.session.query(StaticResults).filter_by(id=driver.static_results).first()
        if static_res is not None and static_res.concat_dos_device_str is not None:
            dos_strings = [s for s in static_res.concat_dos_device_str.split(',') if s is not None and len(s) > 0]
            if len(dos_strings) == 0:
                #app.logger.info(f"Driver {driver.id} not added to the fuzzing queue bc no dos device strings.")
                return False

            sign_res = db.session.query(SignResults).filter_by(id=driver.sign_results).first()
            if sign_res is None or sign_res.verified != "Signed":
                #app.logger.info(f"Driver {driver.id} not added to the fuzzing queue bc not signed.")
                return False
            
            # create the seeds as payloads
            seeds = create_ioctl_seeds_for(driver.id, driver)
            worked = False
            for dos_device_str in dos_strings:
                if any([strange in dos_device_str for strange in ['%']]):
                    prio -= 20 # strange one should be disincentivized
                if static_res.security_str is not None and len(static_res.security_str) > 0:
                    prio -= 80 # very likely secured down somehow

                # further disincentivize based on the certificate, less prio for those by microsoft as first signer
                signature = db.session.query(Signatures).filter_by(sign_result=sign_res.id).first()
                if signature is not None and len(signature.signers) > 0:
                    first_signer = signature.signers[0].name
                    if first_signer == "Microsoft Windows":
                        prio -= 30
                
                prio = max(0, prio)
                try:
                    res, _ = fuzzing_queue_add_internal(driver.id, priority=prio, seeds=seeds, dos_device_str=dos_device_str)
                    if 'success' in res:
                        worked = True
                    #else:
                    #    app.logger.error(f"Could not add driver {driver.id} to the fuzzing queue: {res['error']}")
                except Exception as e:
                    app.logger.error(f"Could not add driver {driver.id} to the fuzzing queue for {dos_device_str}: {e}")
            # delete the seeds that were not used
            if not worked:
                for seed in seeds:
                    db.session.delete(seed)
            return worked
        return False
    return False


@app.route('/fuzzing-queue', methods=['POST'])
def fuzzing_queue_add_custom():
    """Add a new item to the fuzzing queue."""
    try:
        data = request.json
        # required: driver
        if 'driver' not in data:
            return {'error': 'No driver provided for which to fuzz!'}, 400
        driver = db.session.query(Drivers).filter_by(id=data['driver']).first()
        if driver is None:
            return {'error': 'Driver not found'}, 404
        
        # optional with defaults
        priority = 0
        max_runtime = 43200
        max_last_crash = None
        max_last_any = None
        if 'priority' in data:
            priority = data['priority']
        if 'max_runtime' in data:
            max_runtime = data['max_runtime']
        if 'max_last_crash' in data:
            max_last_crash = data['max_last_crash']
        if 'max_last_any' in data:
            max_last_any = data['max_last_any']

        # use the given, or take the first one in the static results
        dos_device_str = None
        if 'dos_device_str' in data:
            dos_device_str = data['dos_device_str']
        else:
            # get the first of the concat_dos_device_str from the static results
            static_res = db.session.query(StaticResults).filter_by(id=driver.static_results).first()
            app.logger.info(f"Static results: {len(static_res.concat_dos_device_str.split(','))}")
            if static_res is None or static_res.concat_dos_device_str is None or len(static_res.concat_dos_device_str.split(',')) == 0:
                return {'error': 'No concat_dos_device_str provided for the fuzzing and none found!'}, 400
                
            dos_device_str = static_res.concat_dos_device_str.split(',')[0]

        # check if the seeds exist
        seeds = []
        if 'seeds' in data and len(data['seeds']) > 0:
            for seed_id in data['seeds']:
                seed = db.session.query(FuzzPayload).filter_by(id=seed_id).first()
                if seed is None:
                    return {'error': f'Seed {seed_id} not found'}, 404
                seeds.append(seed)
        else:
            # if no given seeds, create them from the ioctl comp found
            seeds = create_ioctl_seeds_for(None, driver)

        return fuzzing_queue_add_internal(driver.id, priority, seeds, dos_device_str, max_runtime, max_last_crash, max_last_any)
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/extractions/<int:ogfile_id>')
def extractions(ogfile_id):
    """Get all extractions of an ogfile."""
    return {'error': 'Not implemented yet'}, 501
    try:
        ogf = db.session.query(OgFiles).filter_by(file=ogfile_id).first()
        if ogf is None:
            return {'error': 'OgFiles not found'}, 404
        if ogf.extracted == False:
            return {'error': 'No extractions for this OgFiles'}, 405
        extractions = [model_to_dict(e) for e in Extractions.query.filter_by(ogfile=ogfile_id).all()]
        return {'extractions': extractions}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/extractions', methods=['POST'])
def add_extraction():
    """Adds the new_ogfile to the ogfile as an extraction."""
    infos = request.json
    if 'ogfile' not in infos:
        return {'error': 'No ogfile provided'}, 400
    if 'new_ogfile' not in infos:
        return {'error': 'No new_ogfile provided'}, 400
    try:
        with transaction(raiseExc=True):
            ogf = db.session.query(OgFiles).filter_by(id=infos['ogfile']).first()
            if ogf is None:
                return {'error': 'OgFiles not found'}, 404
            new_ogf = db.session.query(OgFiles).filter_by(id=infos['new_ogfile']).first()
            if new_ogf is None:
                return {'error': 'New OgFiles not found'}, 404
            # add the new ogfile as an extraction
            ext = Extractions(ogfile=ogf.id, file=new_ogf.file, created_at=datetime.now())
            db.session.add(ext)
            return {'success': True}, 200
    except Exception as e:
        if 'violates unique constraint' in str(e):
            return {'error': 'Extraction already exists'}, 409
        return {'error': str(e)}, 500

@app.route('/ogfile-drivers/<int:ogfile_id>')
def drivers_ogfile(ogfile_id):
    """Get all drivers of an ogfile."""
    try:
        ogf = db.session.query(OgFiles).filter_by(file=ogfile_id).first()
        if ogf is None:
            return {'error': 'OgFiles not found'}, 404
        drivers = [{
            'id': d.id,
            'created_at': d.created_at,
            'file': d.file,
        } for d in Drivers.query.filter(Drivers.file==ogf.file).all()]
        return {'drivers': drivers}, 200
    except Exception as e:
       return {'error': str(e)}, 500

def drivers_list_query_to_json(query):
    full_list = []
    seen_driver_ids = set()

    for d, f, sr, pr, og_files in query.all():
        if d.id in seen_driver_ids:
            continue
        seen_driver_ids.add(d.id)

        first_signer = None
        if sr is not None and sr.verified == "Signed":
            signature = db.session.query(Signatures).filter_by(sign_result=sr.id).first()
            if signature is not None:
                first_signer = signature.signers[0].name if len(signature.signers) > 0 else None

        full_list.append({
            'id': d.id,
            'filename': f.filename,
            'sha256': f.sha256,
            'sha1': f.sha1,
            'architecture': str(f.architecture),
            'file': d.file,
            #'created_at': d.created_at,
            'tag': d.tag,
            'verified': sr.verified if sr is not None else None,
            'by': first_signer,
            'ida_ret_code': pr.ret_code if pr is not None else None,
            'og_file_id': og_files.id,
            'origin': og_files.origin,
        })

    return full_list

@app.route('/drivers')
def drivers():
    """Get all drivers."""
    try:
        # return the arch, file, filename, id, sha1, sha256, tag, ogfiles, verified from sign_results, ret_code from path_results
        query = db.session.query(Drivers, Files, SignResults, PathResults, OgFiles)\
            .outerjoin(Files, Files.id == Drivers.file)\
            .outerjoin(SignResults, SignResults.id == Drivers.sign_results)\
            .outerjoin(PathResults, PathResults.id == Drivers.path_results)\
            .outerjoin(OgFiles, OgFiles.file == Drivers.file)
        
        return {'drivers': drivers_list_query_to_json(query)}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/drivers-filter/origin/<origin>', methods=['GET'])
def drivers_by_ogfile_origin(origin):
    """Get all drivers where at least one relevant ogfile is like the origin."""
    try:
        query = db.session.query(Drivers, Files, SignResults, PathResults, OgFiles)\
            .join(OgFiles, OgFiles.file == Drivers.file).filter(OgFiles.origin.like(f"%{origin}%"))\
            .outerjoin(Files, Files.id == Drivers.file)\
            .outerjoin(SignResults, SignResults.id == Drivers.sign_results)\
            .outerjoin(PathResults, PathResults.id == Drivers.path_results)
        
        return {'drivers': drivers_list_query_to_json(query)}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/drivers-filter/imports/<imp>', methods=['GET'])
def drivers_by_import(imp):
    """Get all drivers that import the given function."""
    try:
        # first get all all functions that are like the import name
        # imp can be a comma separated list of imports
        imports = [i.strip() for i in imp.split(',') if len(i.strip()) > 0]
        list_func_ids = [
            db.session.query(Functions.id).filter(Functions.name.like(f"%{imp}%")).all()
            for imp in imports
        ]

        # then get all drivers that have one for each of the functions in the list
        query = db.session.query(Drivers, Files, SignResults, PathResults, OgFiles)\
            .join(StaticResults, StaticResults.id == Drivers.static_results)
        for func_ids in list_func_ids:
            query = query.filter(StaticResults.imports.any(Functions.id.in_([f[0] for f in func_ids])))
        query = query\
            .outerjoin(Files, Files.id == Drivers.file)\
            .outerjoin(SignResults, SignResults.id == Drivers.sign_results)\
            .outerjoin(PathResults, PathResults.id == Drivers.path_results)\
            .outerjoin(OgFiles, OgFiles.file == Drivers.file)\
            .distinct(Drivers.id)

        return {'drivers': drivers_list_query_to_json(query)}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/driver-tags', methods=['GET'])
def driver_tags():
    """Get all possible driver tags."""
    return {'tags': [tag for tag in Tags]}

@app.route('/driver-tags/<int:driver_id>', methods=['PUT'])
def driver_tag(driver_id):
    """Update the specified driver with the specified tag."""
    try:
        tag = request.json
        # Sanity checks:
        if 'tag' not in tag:
            return {'error': 'Tag not found'}, 400
        
        newtag = tag['tag']
        with transaction():
            driver = db.session.get(Drivers, driver_id)
            if driver is None:
                return {'error': 'Driver not found'}, 404
            
            # only some tags are updatable
            if driver.tag not in [Tags.known_vulnerable, Tags.not_vulnerable, Tags.vulnerable, Tags.poced]:
                driver.tag = newtag
            elif newtag in [Tags.poced, Tags.known_vulnerable, Tags.vulnerable, Tags.not_vulnerable]:
                driver.tag = newtag
            else:
                return {'error': f'Tag {driver.tag} not updatable'}, 400
            
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/todo-signatures')
def driver_signatures_todo():
    """Get all drivers that do not have a signature result."""
    try:
        return {'drivers': [{
            'id': d.id,
            'filename': f.filename,
            'sha256': f.sha256,
            'file': d.file,
        } for d, f in db.session.query(Drivers, Files).outerjoin(Files, Files.id == Drivers.file).filter(Drivers.sign_results==None)]}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/driver-signature/<int:driver_id>', methods=['POST'])
def driver_signature_results(driver_id):
    """Update the specified driver with the signature results."""
    try:
        sign_results = request.json
        with transaction():
            driver = db.session.get(Drivers, driver_id)
            if driver is None:
                return {'error': 'Driver not found'}, 404
            
            # Add the cert results as a note
            note = Notes(title="cert", content=json.dumps(sign_results), isfor=driver.file, created_at=datetime.now())
            db.session.add(note)

            # Now actually add the cert results
            cert = SignResults(verified=sign_results['Verified'], company=sign_results['Company'], description=sign_results['Description'], product=sign_results['Product'], prod_version=sign_results['Prod version'], file_version=sign_results['File version'], created_at=datetime.now())
            db.session.add(cert)

            # if the cert has the Verified status Signed, it is valid
            # but some certs are not time valid, which still counts as valid for windows...
            # TODO What counts as valid?
            cert.valid = sign_results['Verified'] == "Signed"

            # Save the reference
            reload_db_obj(cert)
            driver.sign_results = cert.id

            if 'Signatures' not in sign_results:
                app.logger.warn(f"Driver {driver_id} has no signatures?")
            else:
                # add all the signatures of the driver
                for signature in sign_results['Signatures']:
                    signing_date = None
                    if signature['Signing date'] != "n/a":
                        signing_date = datetime.strptime(signature['Signing date'], "%I:%M %p %m/%d/%Y")
                    sig = Signatures(signing_date=signing_date, catalog=signature['Catalog'], sign_result=cert.id)
                    db.session.add(sig)
                    reload_db_obj(sig)
                    
                    # For each signer first check if it already exists, else add it
                    for signer in signature['Signers']:
                        valid_from = datetime.strptime(signer['Valid from'], "%I:%M %p %m/%d/%Y")
                        valid_to = datetime.strptime(signer['Valid to'], "%I:%M %p %m/%d/%Y")
                        sign = db.session.query(Signers).filter_by(name=signer['Signer'], cert_status=signer['Cert Status'], valid_from=valid_from, valid_to=valid_to).first()
                        if sign is None:
                            sign = Signers(name=signer['Signer'], cert_status=signer['Cert Status'], cert_issuer=signer['Cert Issuer'], valid_from=valid_from, valid_to=valid_to)
                            db.session.add(sign)
                            reload_db_obj(sign)
                        sig.signers.append(sign)
                # end add signatures

        return {'success': True}, 200
    except Exception as e:
        app.logger.error(str(e))
        return {'error': str(e)}, 500

@app.route('/driver-signature/<int:driver_id>', methods=['GET'])
def driver_signature(driver_id):
    """Get the signature results of a driver."""
    try:
        driver = db.session.get(Drivers, driver_id)
        if driver is None:
            return {'error': 'Driver not found'}, 404
        if driver.sign_results is None:
            return {'error': 'Driver has no signature results'}, 404
        cert = db.session.get(SignResults, driver.sign_results)
        if cert is None:
            return {'error': 'Certificate results not found'}, 404
        result = model_to_dict(cert)
        result['signatures'] = []
        for sig in db.session.query(Signatures).filter_by(sign_result=cert.id).all():
            sig_result = model_to_dict(sig)
            sig_result['signers'] = [model_to_dict(sign) for sign in sig.signers]
            result['signatures'].append(sig_result)
        return {'signature': result}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/todo-paths/<arch>')
def driver_paths_todo(arch):
    """Get a set of drivers that do not have path results and are of the given architecture."""
    # TODO redo into multiple queues; s.t. lower timeout instances won't retake the same driver
    try:
        return {
        'drivers': sorted([{
            'id': d.id,
            'filename': f.filename,
            'sha256': f.sha256,
            'file': d.file,
            } for d, f in db.session.query(Drivers, Files)\
                .outerjoin(Files, Files.id == Drivers.file)\
                .filter(Drivers.path_results==None)\
                .distinct(Files.filename)
            if arch in str(f.architecture)
        #], key=lambda x: x['file'], reverse=True)
        ], key=lambda k: random.random())
        }, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/driver-paths/<int:driver_id>', methods=['DELETE'])
def driver_path_delete(driver_id):
    """Delete the path results of the specified driver, hence it will be redone from scratch."""
    try:
        with transaction():
            driver = db.session.get(Drivers, driver_id)
            if driver is None:
                return {'error': 'Driver not found'}, 404
            if driver.path_results is None:
                return {'error': 'Driver has no path results'}, 404
            else:
                path_res = db.session.get(PathResults, driver.path_results)
                if path_res is not None:
                    db.session.query(Paths).filter_by(isfor=path_res.id).delete()
                    db.session.delete(path_res)
                    driver.path_results = None
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/driver-paths/<int:driver_id>', methods=['POST'])
def driver_path_results(driver_id):
    """Update the specified driver with the path results."""
    try:
        path_results = request.json
        with transaction():
            driver = db.session.get(Drivers, driver_id)
            if driver is None:
                return {'error': 'Driver not found'}, 404
            if driver.path_results is not None:
                return {'error': 'Driver already has path results'}, 400
            
            # Add the IDA log as a note
            note = Notes(title="ida_log", content=json.dumps(path_results['ida_log']), isfor=driver.file, created_at=datetime.now())
            db.session.add(note)
            
            # add the path results
            path_res = PathResults(ret_code=path_results['ret_code'],
                            type=path_results['handler_type'],
                            handler_addrs=str(path_results['handler_addrs']),
                            combined_sub_functions=path_results['combined_sub_functions'] if 'combined_sub_functions' in path_results else 0,
                            ioctl_comp=json.dumps(path_results['ioctl_comp']) if 'ioctl_comp' in path_results else None,
                            created_at=datetime.now())
            db.session.add(path_res)
            reload_db_obj(path_res)
            driver.path_results = path_res.id

            if path_res.ret_code < 0:
                app.logger.warn(f"The pathing results for driver {driver.id} failed with {path_res.ret_code}!")

            for p in path_results['target_paths'] + path_results['helper_paths']:
                p_new = Paths(path=str(p['path']), name=p['name'], context=p['context'], isfor=path_res.id)
                db.session.add(p_new)
                path_res.paths.append(p_new)
            
            # if there are wdf functions, add them to the static result of this driver
            if 'wdf_functions' in path_results and len(path_results['wdf_functions']) > 0:
                static_res = db.session.query(StaticResults).filter_by(id=driver.static_results).first()
                if static_res is None:
                    app.logger.error(f"No static results for driver {driver.id} found, but wanted to add wdf_functions?")
                else:
                    # all wdf functions should start with pfn
                    func_names = set([func[3:] for func in path_results['wdf_functions'] if len(func) > 3])
                    appendFunctionsStaticResults(func_names, static_res)
            
            # if this driver is unknown, has ioctl comp, add it to the fuzzing queue
            possibly_fuzz(driver, path_res, path_results['ret_code'])

        return {'success': True}, 200
    except Exception as e:
        app.logger.error(str(e))
        return {'error': str(e)}, 500

@app.route('/todo-fuzzing/<arch>')
def driver_fuzzing_todo(arch="AMD64"):
    """Get the next driver in the list to fuzz for that architecture."""
    # get the information from the fuzzQueue
    next_drivers = db.session.query(FuzzQueue)\
        .filter(FuzzQueue.state==FuzzState.queued)\
        .order_by(FuzzQueue.priority.desc()).all()
    if next_drivers is None:
        return {'error': 'No drivers to fuzz'}, 404
    
    for next_driver in next_drivers:
        # get the driver information
        driver, file = db.session.query(Drivers, Files).outerjoin(Files, Files.id == Drivers.file)\
                    .filter(Drivers.id==next_driver.driver).first()

        if driver is None:
            app.logger.error(f"Driver {next_driver.driver} not found in the database?")
            return {'error': 'Driver within fuzzQueue not found?'}, 404
        
        if file is None:
            app.logger.error(f"File {driver.file} not found in the database?")
            return {'error': 'File within driver for fuzzQueue not found?'}, 404

        # check the architecture
        if arch not in str(file.architecture):
            continue

        ret = {
            'id': next_driver.id,
            'driver': {
                'dos_device_str': next_driver.dos_device_str,
                'name': file.filename,
                'id': driver.id,
                'file': driver.file,
                'arch': str(file.architecture)[5:],
            },
            'configuration': {
                'max_runtime': next_driver.max_runtime,
                'max_last_crash': next_driver.max_last_crash,
                'max_last_any': next_driver.max_last_any,
                'seeds': list(set([s.payload for s in next_driver.seeds]))
            }
        }
        return ret, 200
    return {'error': 'No drivers to fuzz'}, 404

@app.route('/driver-fuzzing/<int:fuzz_queue_id>', methods=['PUT'])
def driver_fuzzing_update(fuzz_queue_id):
    """Update the DB fuzzing state with the actual fuzzing state."""
    try:
        with transaction():
            fuzz_queue = db.session.get(FuzzQueue, fuzz_queue_id)
            if fuzz_queue is None:
                return {'error': 'FuzzQueue not found'}, 404

            state = request.json
            if 'state' not in state:
                return {'error': 'No state provided'}, 400
            if state['state'] not in [FuzzState.running, FuzzState.done, FuzzState.errored]:
                return {'error': 'Invalid state provided'}, 400

            # update the state
            fuzz_queue.state = state['state']
            if state['state'] in [FuzzState.done, FuzzState.errored]:
                fuzz_queue.finished_at = datetime.now()

        return {'success': True}, 200
    except Exception as e:
        app.logger.error(str(e))
        return {'error': str(e)}, 500

@app.route('/driver-fuzzing/<int:driver_id>', methods=['POST'])
def driver_fuzzing_results(driver_id):
    """Update the specified driver with the fuzzing results."""
    try:
        fuzz_results = request.json
        if 'version' not in fuzz_results:
            return {'error': 'No version given!'}, 400
        if 'payloads' not in fuzz_results or 'stats' not in fuzz_results:
            return {'error': 'Invalid fuzzing results!'}, 400
        payloads = fuzz_results['payloads']
        stats = fuzz_results['stats']

        driver = db.session.get(Drivers, driver_id)
        if driver is None:
            return {'error': 'Driver not found'}, 404
        
        if 'fuzzing_id' not in fuzz_results:
            app.logger.error(f"No fuzzing_id in the results for driver {driver.id}")
        else:
            set_queue_to = FuzzState.done
        if 'error' in fuzz_results or stats['total_execs'] == 0:
            set_queue_to = FuzzState.errored
            app.logger.error(f"Error in fuzzing results for driver {driver.id}: {fuzz_results}")
        
        fuzz_queue = db.session.get(FuzzQueue, fuzz_results['fuzzing_id'])
        if fuzz_queue is not None:
            with transaction():
                fuzz_queue.state = set_queue_to
                fuzz_queue.finished_at = datetime.now()

        with transaction():
            fuzz_res = db.session.query(FuzzingResults).filter_by(id=driver.fuzzing_results).first()
            if fuzz_res is not None:
                #app.logger.info(f"Updating existing fuzzing results for driver {driver.id} with {fuzz_res.id}")
                fuzz_res.runtime += stats['runtime']
                fuzz_res.total_execs += stats['total_execs']
                fuzz_res.created_at = datetime.now()

                # last run values
                fuzz_res.p_coll = stats['p_coll']
                fuzz_res.total_reloads = stats['total_reloads']
                fuzz_res.paths_total = stats['paths_total']
                fuzz_res.bb_covered = stats['bb_covered']
            else:
                fuzz_res = FuzzingResults(runtime=stats['runtime'], total_execs=stats['total_execs'], p_coll=stats['p_coll'], total_reloads=stats['total_reloads'], paths_total=stats['paths_total'], bb_covered=stats['bb_covered'], created_at=datetime.now())
                db.session.add(fuzz_res)
                reload_db_obj(fuzz_res)
                driver.fuzzing_results = fuzz_res.id
            
            # add the payloads
            payload_types = ['crash', 'kasan', 'timeout', 'regular']
            for pt in payload_types:
                for p in payloads[pt]:
                    payload = FuzzPayload(payload=p['FullData'], type=pt, ioctl=p['IOCTL'], created_at=datetime.now(), version=fuzz_results['version'])
                    db.session.add(payload)
                    fuzz_res.payloads.append(payload)
            
        return {'success': True}, 200
    except Exception as e:
        app.logger.error(str(e))
        return {'error': str(e)}, 500

@app.route('/driver-fuzzing/<int:driver_id>', methods=['GET'])
def driver_fuzzing(driver_id):
    """Get the fuzzing results of a driver."""
    try:
        driver = db.session.get(Drivers, driver_id)
        if driver is None:
            return {'error': 'Driver not found'}, 404
        fuzz_res = db.session.query(FuzzingResults).filter_by(id=driver.fuzzing_results).first()
        if fuzz_res is None:
            return {'error': 'Fuzzing results not found'}, 404
        result = model_to_dict(fuzz_res)
        result['payloads'] = [model_to_dict(p) for p in fuzz_res.payloads]
        return {'fuzzing': result}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/driver-paths/<int:driver_id>', methods=['GET'])
def driver_path(driver_id):
    """Get the path results of a driver."""
    try:
        driver = db.session.get(Drivers, driver_id)
        if driver is None:
            return {'error': 'Driver not found'}, 404
        if driver.path_results is None:
            return {'error': 'Driver has no path results'}, 404
        path_res = db.session.get(PathResults, driver.path_results)
        if path_res is None:
            return {'error': 'Path results not found'}, 404
        result = model_to_dict(path_res)
        result['handler_addrs'] = json.loads(result['handler_addrs'])
        result['ioctl_comp'] = json.loads(result['ioctl_comp']) if result['ioctl_comp'] is not None else []
        result['paths'] = [model_to_dict(p) for p in path_res.paths]
        for p in result['paths']:
            p['path'] = json.loads(p['path'])
        return {'path': result}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/drivers/<int:driver_id>')
def driver_by(driver_id):
    """Get a driver by its id, with all of its results."""
    try:
        d, f, sr, pr, fr = db.session.query(Drivers, Files, StaticResults, PathResults, FuzzingResults)\
            .filter_by(id=driver_id)\
            .outerjoin(Files)\
            .outerjoin(StaticResults)\
            .outerjoin(PathResults)\
            .outerjoin(FuzzingResults)\
            .first()
        if d is None:
            return {'error': 'Driver not found'}, 404

        stat_res = None
        if sr is not None:
            stat_res = model_to_dict(sr)
            # return in order of interesting
            imp = sorted(sr.imports, key=lambda x: x.interesting, reverse=True)
            stat_res['imports'] = [i.name for i in imp]

        driv_sig = driver_signature(driver_id)
        sign_res = driv_sig[0]['signature'] if driv_sig[1] == 200 else None 

        fuzz_res = model_to_dict(fr) if fr is not None else None
        if fuzz_res is not None:
            fuzz_res['payloads'] = [model_to_dict(p) for p in fr.payloads]

        return {'driver': {
            'id': d.id,
            'tag': d.tag,
            'filename': f.filename,
            'sha256': f.sha256,
            'sha1': f.sha1,
            'ssdeep': f.ssdeep,
            'architecture': str(f.architecture),
            'file': d.file,
            'static_results': stat_res,
            'sign_results': sign_res,
            'path_results': model_to_dict(pr) if pr is not None else None,
            'fuzzing_results': fuzz_res,
        }}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/driver-id/<driver_hash>', methods=['GET'])
def driver_id_by(driver_hash):
    """Returns the driver ID for the given SHA1 or SHA256 hash."""
    try:
        if len(driver_hash) == 40:
            # SHA1
            driver = db.session.query(Drivers).join(Files).filter(Files.sha1==driver_hash).first()
        elif len(driver_hash) == 64:
            # SHA256
            driver = db.session.query(Drivers).join(Files).filter(Files.sha256==driver_hash).first()
        else:
            return {'error': 'Invalid hash length'}, 400
        if driver is None:
            return {'error': 'Driver not found'}, 404
        return {'driver_id': driver.id}, 200
    except Exception as e:
       return {'error': str(e)}, 500

@app.route('/functions', methods=['GET'])
def functions_info():
    """Returns all functions currently existing, with the count of how often they are seen, ordered by interesting."""
    try:
        functions = db.session.query(Functions)\
            .order_by(Functions.interesting.desc()).all()
        return {'functions': [{
            'name': f.name,
            'count': len(f.static_result),
            'interesting': f.interesting
        #} for f in functions if len(f.static_result) > 0]}, 200
        } for f in functions]}, 200
    except Exception as e:
        return {'error': str(e)}, 500


@app.route('/known-vulnerable-list', methods=['GET'])
def known_vulnerable_list():
    """Returns all known vulnerable drivers."""
    try:
        return {'drivers': [model_to_dict(d) for d in db.session.query(KnownVulnerableDrivers).all()]}, 200
    except Exception as e:
        return {'error': str(e)}, 500

#### HELPER FUNCTIONS FOR USERS ####
@app.route('/db-stats', methods=['GET'])
def db_stats():
    """Returns a json with some statistics about the current database."""
    # - Number of files
    # - Number of drivers, for each architecture, total, known vulnerable, vulnerable, not vulnerable, poced
    # - Number of functions, interesting functions, total functions in drivers, functions in more than 100 drivers
    # - Number of missing vulnerable driver files
    # - Total size of storage for all files, for all drivers
    try:
        # Number of files
        num_files = db.session.query(Files).count()

        # Number of drivers
        num_drivers = db.session.query(Drivers).count()
        num_drivers_arch = {}
        num_drivers_tags = {}
        for arch in Arch:
            num_drivers_arch[arch] = db.session.query(Drivers).join(Files).filter(Files.architecture==arch).count()
        for tag in Tags:
            num_drivers_tags[tag] = db.session.query(Drivers).filter(Drivers.tag==tag).count()

        # Number of functions
        num_functions = db.session.query(Functions).count()
        num_interesting_functions = db.session.query(Functions).filter(Functions.interesting>0).count()
        
        functions = db.session.query(Functions)\
            .order_by(Functions.interesting.desc()).all()
        num_functions_drivers_100 = len([f for f in functions if len(f.static_result) > 100])

        # Number of missing vulnerable driver files
        num_missing_files = db.session.query(KnownVulnerableDrivers).filter(KnownVulnerableDrivers.file==None).count()

        # Total size of storage for all files, for all drivers
        # as direct queries bc summing in python is slow
        total_size_files = sum([f.size for f in db.session.query(Files).filter(Files.path.is_not(None)).all()])
        total_size_drivers = sum([f.size for f in db.session.query(Files).filter(Files.path.is_not(None)).join(Drivers).all()])
        #total_size_files = db.session.query(func.sum(Files.size)).scalar()
        
        return {
            'num_files': num_files,
            'num_drivers': num_drivers,
            'num_drivers_arch': num_drivers_arch,
            'num_drivers_tags': num_drivers_tags,
            'num_functions': num_functions,
            'num_interesting_functions': num_interesting_functions,
            'num_functions_drivers_100': num_functions_drivers_100,
            'num_missing_files': num_missing_files,
            'total_size_files': total_size_files,
            'total_size_drivers': total_size_drivers,
        }, 200
    except Exception as e:
        return {'error': str(e)}, 500


@app.route('/help', methods=['GET'])
def routes_info():
    """Print all defined routes and their endpoint docstrings."""
    routes = []
    for rule in app.url_map.iter_rules():
        try:
            if rule.endpoint != 'static':
                if hasattr(app.view_functions[rule.endpoint], 'import_name'):
                    import_name = app.view_functions[rule.endpoint].import_name
                    obj = import_string(import_name)
                    routes.append({rule.rule: "%s\n%s" % (",".join(list(rule.methods)), obj.__doc__)})
                else:
                    routes.append({rule.rule: app.view_functions[rule.endpoint].__doc__})
        except Exception as exc:
            routes.append({rule.rule: 
                           "(%s) INVALID ROUTE DEFINITION!!!" % rule.endpoint})
            route_info = "%s => %s" % (rule.rule, rule.endpoint)
            app.logger.error("Invalid route: %s" % route_info, exc_info=True)
            # func_list[rule.rule] = obj.__doc__

    return jsonify(code=200, data=routes)

@app.route('/health')
def health():
    if health_status:
        resp = jsonify(health="healthy")
        resp.status_code = 200
    else:
        resp = jsonify(health="unhealthy")
        resp.status_code = 500

    return resp

#### PREDEFINED VALUES FOR THE DATABASE ####
def known_vulnerable_drivers():
    """Loads all currently known vulnerable drivers into the database."""
    app.logger.info("Loading predefined known vulnerable drivers...")
    with open('./knownVulnerableDrivers.csv', 'r') as f:
        reader = csv.reader(f)
        next(reader) # skip the header
        for row in reader:
            try:
                filename,sha256,origin,description = row
                sha256 = sha256.lower()
                with transaction(raiseExc=True):
                    # first see if sha256 is already in the database
                    entry = db.session.query(KnownVulnerableDrivers).filter_by(sha256=sha256).first()
                    if entry is None:
                        entry = KnownVulnerableDrivers(sha256=sha256, filename=filename, origin=origin, description=description)
                        db.session.add(entry)
            except Exception as e:
                if "violates unique constraint" in str(e):
                    # search and update the existing entry to have both a filename and a sha256
                    entry = db.session.query(KnownVulnerableDrivers).filter_by(filename=filename).first()
                    if entry is None:
                        app.logger.error("Could not find entry for filename or sha256 %s, but unique error?" % sha256)
                        continue
                    if entry.sha256 is None:
                        entry.sha256 = sha256
                    elif entry.sha256.lower() != sha256.lower():
                        app.logger.error("Entry %s has different sha256 %s" % (entry.filename, entry.sha256))
                else:
                    app.logger.error("Loading predefined known vulnerable drivers:", str(e))
    app.logger.info("Predefined known vulnerable drivers added!")

def predefined_interesting_functions():
    """Adds all functions to the database that are interesting."""
    app.logger.info("Loading predefined interesting functions...")
    with open('./interestingFunctions.csv', 'r') as f:
        reader = csv.reader(f)
        next(reader) # skip the header
        for row in reader:
            try:
                functionname, interesting = row
                with transaction(raiseExc=True):
                    db.session.add(Functions(name=functionname, interesting=interesting))
            except Exception as e:
                if "violates unique constraint" in str(e):
                    # it already exists, update the interesting value
                    with transaction():
                        function = db.session.query(Functions).filter_by(name=functionname).first()
                        if function is not None:
                            function.interesting = interesting
                else:
                    app.logger.error("Loading predefined interesting functions:", str(e))
    app.logger.info("Predefined interesting functions added!")

def fix_known_vuln_underlying_files():
    app.logger.info("Fixing known underlying files!")
    for known_vul in db.session.query(KnownVulnerableDrivers).all():
        if known_vul.sha256 is not None:
            with transaction():
                # get the file with the sha256
                file = db.session.query(Files).filter_by(sha256=known_vul.sha256).first()
                if file is None:
                    known_vul.file = None
                else:
                    known_vul.file = file.id
    app.logger.info("Done fixing!")

def clear_failed_fuzzing_notes():
    app.logger.info("Clearing failed fuzzing notes...")
    with transaction():
        db.session.query(Notes).filter(Notes.title=="fuzzing-setup", Notes.content.like("Failed to setup fuzzing: %")).delete()
    app.logger.info("Done clearing!")

def rerun_unsucessful_pathing():
    raise NotImplementedError("This function is currently locked!")
    app.logger.info("Deleting all pathing for unsucessful runs...")
    for driver in db.session.query(Drivers).all():
        if driver.path_results is not None:
            path_res = db.session.query(PathResults).filter_by(id=driver.path_results,type=HandlerType.WDF).first()
            if path_res is not None: # and path_res.ret_code < 100:
                with transaction():
                    driver.path_results = None
                    db.session.query(Paths).filter_by(isfor=path_res.id).delete()
                    db.session.delete(path_res)

                    # delete all functions that were added thorugh the pathing results
                    # that is all functions starting with Wdf,
                    # except WdfVersionBindClass, WdfVersionBind, WdfVersionUnbind, WdfVersionUnbindClass
                    # For any duplicate errors use the following query through pgAdmin4:
# DELETE FROM "functions_staticResults"
# WHERE functions_id IN
#     (SELECT id
#     FROM 
#         (SELECT id FROM functions
# 		WHERE name LIKE '%Wdf%'
# 		AND name NOT LIKE 'WdfVersion%')
# 	)
                    static_res = db.session.query(StaticResults).filter_by(id=driver.static_results).first()
                    if static_res is not None and len(static_res.imports) > 0:
                        for func in static_res.imports:
                            if func.name is None:
                                app.logger.error(f"Function {func.id} has no name?")
                                continue
                            if func.name.startswith("Wdf") and not func.name in ["WdfVersionBindClass", "WdfVersionBind", "WdfVersionUnbind", "WdfVersionUnbindClass"]:
                                app.logger.error(f'TO REMOVE: DELETE FROM "functions_staticResults" WHERE "functions_staticResults".functions_id = {func.id} AND "functions_staticResults"."staticResults_id" = {driver.static_results}; from {driver.id}')
                                static_res.imports.remove(func)
                    
                    # delete the ida_log note relevant for this pathing
                    db.session.query(Notes).filter(Notes.title=="ida_log", Notes.isfor==driver.file).delete()
                    app.logger.info(f"Rerunning pathing for driver {driver.id}")

    app.logger.info("Done rerunning!")

if __name__ == "__main__":
    app.logger.setLevel(logging.DEBUG)

    with app.app_context():
        app.logger.info("Starting the coordinator setup...")
        db.create_all()

        #predefined_interesting_functions()
        #known_vulnerable_drivers()

        #fix_known_vuln_underlying_files()
        #clear_failed_fuzzing_notes()
        #rerun_unsucessful_pathing()

    app.logger.info("Coordinator started!")
    app.run(host='0.0.0.0', port=5000, debug=True)
