from run_api import db

class User(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	public_id = db.Column(db.String(50),unique=True)
	name = db.Column(db.String(50))
	password = db.Column(db.String(80))
	admin = db.Column(db.Boolean)


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
	
	#assignee = db.Column(db.Srting(50))
	assignee = db.Column(db.Integer,db.ForeignKey('user.public_id'))
	progress = db.Column(db.String(50))
	
	creation_date = db.Column(db.DateTime, nullable=False)
	due_date = db.Column(db.String(10),nullable=False)
	creator = db.Column(db.Integer,db.ForeignKey('user.id'))
	
class Updates(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	user = db.Column(db.Integer,db.ForeignKey('user.public_id'))
	task = db.Column(db.Integer,db.ForeignKey('task.id'))

class Message(db.Model):
    mid = db.Column(db.Integer, primary_key=True)
    #dt = db.Column(db.String(50),unique=True)
    sender = db.Column(db.Integer,db.ForeignKey('user.id'))
    time_sent = db.Column(db.DateTime, nullable=False)
    message = db.Column(db.String(80))
    reciever = db.Column(db.Integer,db.ForeignKey('user.id'))

class UserTasks(db.Model):
	user_id = db.Column(db.Integer,db.ForeignKey('user.public_id'), primary_key=True)
	task_id = db.Column(db.Integer,db.ForeignKey('task.id'), primary_key=True)
	
class UserChannel(db.Model):
	user_id = db.Column(db.Integer,db.ForeignKey('user.public_id'), primary_key=True)
	channel_id = db.Column(db.Integer,db.ForeignKey('channel.id'), primary_key=True)
	
class UserWorkspace(db.Model):
	user_id = db.Column(db.Integer,db.ForeignKey('user.public_id'), primary_key=True)
	workspace_id = db.Column(db.Integer,db.ForeignKey('workspace.id'), primary_key=True)



