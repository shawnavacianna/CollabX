from flask import Flask,request,jsonify,make_response,render_template,redirect, url_for, flash,current_app,send_from_directory
from run_api import app, db,allowed_uploads
from models import *
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import os
from werkzeug.utils import secure_filename
from forms import UploadForm 




def token_required(f):
	@wraps(f)
	def decorated(*arg, **kwargs):
		token = None
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'Message':'Token is unavailable'})
		try:
			data = jwt.decode(token,app.config['SECRET_KEY'])
			current_user = User.query.filter_by(public_id=data['public_id']).first()
		except:
			return jsonify({'Message':'Token is invalid'}),401
		return f(current_user,*arg, **kwargs)
	return decorated

'''
def admin_required(f):
	@wraps(f)
	def decorated(*arg, **kwargs):
		@token_required
		if not current_user.admin:
			return jsonify({'Message':'You must be an admin to perform this task'})
		return 
'''

@app.route('/home')
def home():
	return render_template('index.html')

@app.route('/elements')
def elements():
	return render_template('elements.html')

@app.route('/generic')
def generic():
	return render_template('generic.html')


@app.route('/login')
def login():
	auth = request.authorization
	if not auth or not auth.username or not auth.password:
		return make_response('Authentication not verified',401,{'WWW-Authenticate':'Basic realm="Login Required!"'})
	user = User.query.filter_by(name=auth.username).first()
	if not user:		
		return make_response('Authentication not verified',401,{'WWW-Authenticate':'Basic realm="Login Required!"'})
	if check_password_hash(user.password,auth.password):
		token = jwt.encode({'public_id':user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
		return jsonify({'token':token.decode('UTF-8')}) 		#return redirect(url_for('home'))
	return make_response('Authentication not verified',401,{'WWW-Authenticate':'Basic realm="Login Required!"'})


'''
@app.route('/logout')
@token_required
def logout(current_user):
	if 
'''

@app.route('/register', methods=['POST'])
def register():
	data = request.get_json()
	hashed_password = generate_password_hash(data['password'],method='sha256')
	new_user = User(public_id=str(uuid.uuid4()), name=data['name'],password=hashed_password,admin=False,channel=data['channel'],workspace=data['workspace'])
	db.session.add(new_user)
	db.session.commit()
	return jsonify({'Message':'You are now a registered member '})
	#return redirect(url_for('home'))

@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(public_id):	
	if not current_user.admin:
		return jsonify({'Message':'You must be an admin to perform this task'})
	user = User.query.filter_by(public_id=public_id).first()	
	if not user:
		return jsonify({'Message':'User does not exist'})

	user.admin=True
	db.session.commit()
	return jsonify({'Message':'The user was promoted'})


'''
HELPER ROUTES TO SEE DATABASE OBJECTS
'''

@app.route('/user',methods=['GET'])
def get_users():
	users =User.query.all()
	output = []
	for user in users:
		user_data={}
		user_data['public_id']=user.public_id
		user_data['name']=user.name
		user_data['password']=user.password
		user_data['admin']=user.admin
		user_data['channel'] = user.channel
		user_data['workspace'] = user.workspace
		output.append(user_data)
	return jsonify({'users':output})

@app.route('/workspace',methods=['GET'])
def get_workspaces():
	workspaces =Workspace.query.all()
	output = []
	for workspace in workspaces:
		workspace_data={}
		workspace_data['name']=workspace.name
		workspace_data['creation_date']=workspace.creation_date
		workspace_data['description']=workspace.description
		workspace_data['creator']=workspace.creator

		output.append(workspace_data)
	return jsonify({'workspaces':output})

@app.route('/channel',methods=['GET'])
def get_channel():
	channels =Channel.query.all()
	output = []
	for channel in channels:
		channel_data={}
		channel_data['name']=channel.name
		channel_data['creation_date']=channel.creation_date
		channel_data['description']=channel.description
		channel_data['creator']=channel.creator

		output.append(channel_data)
	return jsonify({'channels':output})

'''
CREATE & ADD TO WORKSPACE & CHANNEL

'''


@app.route('/channel', methods=['POST'])
@token_required
def create_channel(current_user):
	if not current_user.admin:
		return jsonify({'Message':'You must be an admin to perform this task'})

	data = request.get_json()
	new_channel = Channel(name=data['name'],creation_date=datetime.datetime.utcnow(),description=data['description'],creator=current_user.id)
	db.session.add(new_channel)
	db.session.commit()
	return jsonify({'Message':'Channel was created'})

@app.route('/channel/<public_id>',methods=['PUT'])
@token_required
def add_user_to_channel(current_user,public_id):
	if not current_user.admin:
		return jsonify({'Message':'You must be an admin to perform this task'})
	user = User.query.filter_by(public_id=public_id).first()	
	if not user:
		return jsonify({'Message':'User does not exist'})


	data = request.get_json()
	channel = Channel.query.filter_by(name=data['channel']).first()
	if not channel:
		return jsonify({'Message':'Channel does not exist'})
	user.channel = channel.id
	db.session.commit()
	return jsonify({'Message':'The user was added to the specified channel'})

@app.route('/workspace/<public_id>', methods=['POST','PUT'])
@token_required
def create_workspace(current_user,public_id):
	data = request.get_json()
	new_workspace = Workspace(name=data['name'],creation_date=datetime.datetime.utcnow(),description=data['description'],creator=current_user.id)
	db.session.add(new_workspace)
	db.session.commit()

	if request.method == 'PUT':
		user = User.query.filter_by(public_id=public_id).first()	
		user.admin=True
		db.session.commit()
		return jsonify({'Message':'User is now an admin for this workspace'})
	return jsonify({'Message':'Workspace was created'})

@app.route('/addworkspace/<public_id>',methods=['PUT'])
@token_required
def add_user_to_workspace(current_user,public_id):
	if not current_user.admin:
		return jsonify({'Message':'You must be an admin to perform this task'})
	user = User.query.filter_by(public_id=public_id).first()	
	if not user:
		return jsonify({'Message':'User does not exist'})

	data = request.get_json()
	workspace = Workspace.query.filter_by(name=data['workspace']).first()
	if not workspace:
		return jsonify({'Message':'Workspace does not exist'})
	user.workspace = workspace.id
	db.session.commit()
	return jsonify({'Message':'The user was added to the specified workspace'})


'''
DELETE USER, WORKSPACE, CHANNEL

'''

@app.route('/user/<public_id>',methods=['DELETE'])
def delete_user(public_id):	
	user = User.query.filter_by(public_id=public_id).first()	
	if not user:
		return jsonify({'Message':'User does not exist'})
	db.session.delete(user)
	db.session.commit()
	return jsonify({'Message':'The user was deleted'})

@app.route('/workspace/<name>',methods=['DELETE'])
@token_required
def delete_workspace(current_user,name):	
	if not current_user.admin:
		return jsonify({'Message':'You must be an admin to perform this task'})
	workspace = Workspace.query.filter_by(name=name).first()	
	if not workspace:
		return jsonify({'Message':'Workspace does not exist'})
	db.session.delete(workspace)
	db.session.commit()
	return jsonify({'Message':'The Workspace was deleted'})

@app.route('/channel/<name>',methods=['DELETE'])
@token_required
def delete_channel(current_user,name):	
	if not current_user.admin:
		return jsonify({'Message':'You must be an admin to perform this task'})
	channel = Channel.query.filter_by(name=name).first()	
	if not channel:
		return jsonify({'Message':'Channel does not exist'})
	db.session.delete(channel)
	db.session.commit()
	return jsonify({'Message':'The Channel was deleted'})

'''

 UPLOAD AND DOWNLOAD FILES

'''

@app.route('/upload', methods=['GET','POST'])
#@token_required
def upload():

    uploadForm = UploadForm()

    # Validate file upload on submit
    if request.method == 'POST' and uploadForm.validate_on_submit():

        upload = uploadForm.upload.data
        filename = secure_filename(upload.filename)
        upload.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))

        flash('File Saved', 'success')
        return redirect(url_for('home'))

    return render_template('upload.html',uploadForm = uploadForm)

@app.route('/download/<filename>', methods=['GET'])
def download(filename):
	    uploads = os.path.join(current_app.root_path, app.config['UPLOAD_FOLDER'])
	    return send_from_directory(directory=uploads, filename=filename, as_attachment=True)

'''
@app.route('/viewupload', methods=['GET'])
def view_uploads():
    file_list = get_uploaded_files()
    print (file_list)
    return render_template('files.html', uploaded_files = file_list)
'''

def get_uploaded_files():
    uploads = []
    for cwd, subdirs, files in os.walk(app.config['UPLOAD_FOLDER']):
        for file in files:
            if file.split('.')[-1] in allowed_uploads:
                uploads.append(file)

    return uploads

'''

@app.route('/user/<public_id>',methods=['GET'])
def get_one_user(public_id):
	user = User.query.filter_by(public_id=public_id).first()
	if not user:
		return jsonify({'Message':'User does not exist'})

	user_data ={}		
	user_data['public_id']=user.public_id
	user_data['name']=user.name
	user_data['password']=user.password
	user_data['admin']=user.admin
	return jsonify({'user':user_data})

'''