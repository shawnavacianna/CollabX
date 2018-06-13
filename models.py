from run_api import db

class User(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	public_id = db.Column(db.String(50),unique=True)
	name = db.Column(db.String(50))
	password = db.Column(db.String(80))
	admin = db.Column(db.Boolean)
	channel = db.Column(db.Integer,db.ForeignKey('channel.id'))
	workspace = db.Column(db.Integer,db.ForeignKey('workspace.id'))

class Channel(db.Model):    #download sqliteman to view databases you create here
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(50), nullable=False)
	creation_date = db.Column(db.DateTime, nullable=False)
	description = db.Column(db.String(1000), nullable=False)
	creator = db.Column(db.Integer,db.ForeignKey('user.id'))


class Workspace(db.Model):    
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(50), nullable=False)
	creation_date = db.Column(db.DateTime, nullable=False)
	description = db.Column(db.String(1000), nullable=False)
	creator = db.Column(db.Integer,db.ForeignKey('user.id'))


class Task(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(50), nullable=False)
	description = db.Column(db.String(1000), nullable=False)
	assignee = db.Column(db.String(50))
	creation_date = db.Column(db.DateTime, nullable=False)
	due_date = db.Column(db.DateTime,nullable=False)
	creator = db.Column(db.Integer,db.ForeignKey('user.id'))






