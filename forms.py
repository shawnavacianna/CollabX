from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired

class UploadForm(FlaskForm):
    upload = FileField('files', validators=[
        FileRequired(),
        FileAllowed(['png','jpg','txt','pdf','doc','csv'])
    ])

