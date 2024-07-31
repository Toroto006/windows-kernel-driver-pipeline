from flask_sqlalchemy import SQLAlchemy
from enum import Enum

db = SQLAlchemy()

Base = db.Model


class Arch(str, Enum):

    IA64 = 'IA64'
    AMD32 = 'AMD32'
    AMD64 = 'AMD64'
    ARM32 = 'ARM32'
    ARM64 = 'ARM64'
    ARM16 = 'ARM16'


class Tags(str, Enum):

    errored = 'errored'
    known_vulnerable = 'known_vulnerable'
    not_vulnerable = 'not_vulnerable'
    poced = 'poced'
    unknown = 'unknown'
    vulnerable = 'vulnerable'


class HandlerType(str, Enum):

    WDF = 'WDF'
    WDM = 'WDM'
    unknown = 'unknown'


class FuzzState(str, Enum):

    done = 'done'
    errored = 'errored'
    queued = 'queued'
    running = 'running'

class Files(Base):

    __tablename__ = 'files'

    id = db.Column(db.Integer(), primary_key=True)
    path = db.Column(db.String(), unique=True)
    filename = db.Column(db.String(), nullable=False)
    size = db.Column(db.Integer(), nullable=False)
    architecture = db.Column(db.Enum(Arch))
    sha256 = db.Column(db.String(), nullable=False, unique=True)
    sha1 = db.Column(db.String())
    ssdeep = db.Column(db.String())


signer_signatures = db.Table('signer_signatures',
                    db.Column('signers_id', db.Integer, db.ForeignKey('signers.id')),
                    db.Column('signatures_id', db.Integer, db.ForeignKey('signatures.id'))
                    )


class Signers(Base):

    __tablename__ = 'signers'
    __table_args__ = (db.UniqueConstraint("name", "cert_status", "valid_from", "valid_to"),)

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String())
    cert_status = db.Column(db.String())
    cert_issuer = db.Column(db.String())
    valid_from = db.Column(db.TIMESTAMP())
    valid_to = db.Column(db.TIMESTAMP())


class Signatures(Base):

    __tablename__ = 'signatures'

    id = db.Column(db.Integer(), primary_key=True)
    sign_result = db.Column(db.Integer(), db.ForeignKey('signResults.id'))
    signing_date = db.Column(db.TIMESTAMP())
    catalog = db.Column(db.String())
    signers = db.relationship('Signers', secondary=signer_signatures, backref='signers')


class SignResults(Base):

    __tablename__ = 'signResults'

    id = db.Column(db.Integer(), primary_key=True)
    valid = db.Column(db.Boolean(), default=False)
    verified = db.Column(db.String())
    company = db.Column(db.String())
    description = db.Column(db.String())
    product = db.Column(db.String())
    prod_version = db.Column(db.String())
    file_version = db.Column(db.String())
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


# TODO somehow add unique constraint for the combination?
functions_staticResults = db.Table('functions_staticResults',
                    db.Column('functions_id', db.Integer, db.ForeignKey('functions.id')),
                    db.Column('staticResults_id', db.Integer, db.ForeignKey('staticResults.id'))
                    )


class Functions(Base):

    __tablename__ = 'functions'

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(), unique=True)
    interesting = db.Column(db.Integer(), default=0)


class StaticResults(Base):

    __tablename__ = 'staticResults'

    id = db.Column(db.Integer(), primary_key=True)
    phys_mem = db.Column(db.Boolean())
    concat_dos_device_str = db.Column(db.String())
    security_str = db.Column(db.String())
    imports = db.relationship('Functions', secondary=functions_staticResults, backref='static_result')
    imphash = db.Column(db.String())
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


class Paths(Base):

    __tablename__ = 'paths'

    id = db.Column(db.Integer(), primary_key=True)
    path = db.Column(db.String(), nullable=False)
    name = db.Column(db.String())
    context = db.Column(db.String())
    isfor = db.Column(db.Integer(), db.ForeignKey('pathResults.id'), nullable=False)


class PathResults(Base):

    __tablename__ = 'pathResults'

    id = db.Column(db.Integer(), primary_key=True)
    ret_code = db.Column(db.Integer(), nullable=False)
    type = db.Column(db.Enum(HandlerType))
    handler_addrs = db.Column(db.String())
    paths = db.relationship('Paths', backref='path_results', lazy=True)
    combined_sub_functions = db.Column(db.Integer())
    ioctl_comp = db.Column(db.String())
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


fuzzPayload_fuzzQueue = db.Table('fuzzPayload_fuzzQueue',
                    db.Column('fuzzPayload_id', db.Integer, db.ForeignKey('fuzzPayload.id')),
                    db.Column('fuzzQueue_id', db.Integer, db.ForeignKey('fuzzQueue.id'))
                    )


class FuzzQueue(Base):

    __tablename__ = 'fuzzQueue'

    id = db.Column(db.Integer(), primary_key=True)
    priority = db.Column(db.Integer(), nullable=False, default=0)
    state = db.Column(db.Enum(FuzzState))

    driver = db.Column(db.Integer(), db.ForeignKey('drivers.id'))
    
    dos_device_str = db.Column(db.String(), nullable=False)
    #seeds = db.Column(db.Integer())
    seeds = db.relationship('FuzzPayload', secondary=fuzzPayload_fuzzQueue, backref='fuzz_queue')
    max_runtime = db.Column(db.Integer(), default=43200)
    max_last_crash = db.Column(db.Integer())
    max_last_any = db.Column(db.Integer())
    
    created_at = db.Column(db.TIMESTAMP(), nullable=False)
    finished_at = db.Column(db.TIMESTAMP())
    

class FuzzPayload(Base):

    __tablename__ = 'fuzzPayload'

    id = db.Column(db.Integer(), primary_key=True)
    version = db.Column(db.String(), nullable=False)
    
    ioctl = db.Column(db.String())
    type = db.Column(db.String(), nullable=False)
    payload = db.Column(db.String(), nullable=False)
    
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


fuzzPayload_fuzzingResults = db.Table('fuzzPayload_fuzzingResults',
                    db.Column('fuzzPayload_id', db.Integer, db.ForeignKey('fuzzPayload.id')),
                    db.Column('fuzzingResults_id', db.Integer, db.ForeignKey('fuzzingResults.id'))
                    )


class FuzzingResults(Base):

    __tablename__ = 'fuzzingResults'

    id = db.Column(db.Integer(), primary_key=True)
    
    #payloads = db.Column(db.Integer())
    payloads = db.relationship('FuzzPayload', secondary=fuzzPayload_fuzzingResults, backref='fuzzing_results')

    runtime = db.Column(db.Integer())
    total_execs = db.Column(db.Integer())
    
    p_coll = db.Column(db.Float())
    total_reloads = db.Column(db.Integer())
    paths_total = db.Column(db.Integer())
    bb_covered = db.Column(db.Integer())

    created_at = db.Column(db.TIMESTAMP(), nullable=False)


class Notes(Base):

    __tablename__ = 'notes'

    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String())
    content = db.Column(db.String())
    isfor = db.Column(db.Integer(), db.ForeignKey('files.id'))
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


class OgFiles(Base):

    __tablename__ = 'ogFiles'

    id = db.Column(db.Integer(), primary_key=True)
    origin = db.Column(db.String())
    file = db.Column(db.Integer(), db.ForeignKey('files.id'), nullable=False)
    type = db.Column(db.String())
    extracted = db.Column(db.Boolean(), default=False)
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


class Drivers(Base):

    __tablename__ = 'drivers'

    id = db.Column(db.Integer(), primary_key=True)
    tag = db.Column(db.Enum(Tags))
    file = db.Column(db.Integer(), db.ForeignKey('files.id'), nullable=False)
    static_results = db.Column(db.Integer(), db.ForeignKey('staticResults.id'))
    sign_results = db.Column(db.Integer(), db.ForeignKey('signResults.id'))
    path_results = db.Column(db.Integer(), db.ForeignKey('pathResults.id'))
    fuzzing_results = db.Column(db.Integer(), db.ForeignKey('fuzzingResults.id'))
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


class Extractions(Base):

    __tablename__ = 'extractions'
    __table_args__ = (db.UniqueConstraint("ogfile", "file"),)
    
    id = db.Column(db.Integer(), primary_key=True)
    ogfile = db.Column(db.Integer(), db.ForeignKey('ogFiles.id'), nullable=False)
    file = db.Column(db.Integer(), db.ForeignKey('files.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP(), nullable=False)


class KnownVulnerableDrivers(Base):

    __tablename__ = 'knownVulnerableDrivers'
    __table_args__ = (db.UniqueConstraint("sha256", "filename"),)

    id = db.Column(db.Integer(), primary_key=True)
    sha256 = db.Column(db.String(), nullable=False, unique=True)
    filename = db.Column(db.String())
    description = db.Column(db.String())
    origin = db.Column(db.String())
    file = db.Column(db.Integer(), db.ForeignKey('files.id'))
