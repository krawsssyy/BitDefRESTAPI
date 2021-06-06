from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from datetime import date



class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    producer = db.Column(db.Integer)

class Malware(db.Model):
    __tablename__ = 'Malware'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True)
    type = db.Column(db.String(150))
    creationDate = db.Column(db.String(20))
    lastModified = db.Column(db.String(20))

class Tool(db.Model):
    __tablename__ = 'Tool'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    whatItDoes = db.Column(db.String(150))
    creationDate = db.Column(db.String(20))
    lastModified = db.Column(db.DateTime, onupdate=func.now(), default=func.now())

class Indicator(db.Model):
    __tablename__ = 'Indicator'
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(150), nullable=False)
    creationDate = db.Column(db.String(20))
    lastModified = db.Column(db.DateTime, onupdate=func.now(), default=func.now())

class Relationship(db.Model):
    __tablename__ = 'Relationship'
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    target = db.Column(db.String(20), nullable=False)

class Vulnerability(db.Model):
    __tablename__ = 'Vulnerability'
    cve_id = db.Column(db.String(20), nullable=False, primary_key=True)
