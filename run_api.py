from flask import Flask
from flask_sqlalchemy import SQLAlchemy



app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/shawnavacianna/virtualenvironment/ncb_demo/collabX.db'
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
allowed_uploads = ['png','jpg','txt','pdf','doc','csv']

db = SQLAlchemy(app)

# You have to import you views here since python is an interpreted language and all the above has to be loaded first.
from views import *


if __name__=='__main__':
    app.run(debug=True)