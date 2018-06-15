from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired

class UploadForm(FlaskForm):
    upload = FileField('', validators=[
        FileRequired(),
        FileAllowed(['png','jpg','txt','pdf','doc','csv'])
    ])


class SignUpForm(FlaskForm):
    name = StringField('name', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    workspace = StringField('name')

