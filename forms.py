from wtforms import Form, StringField, PasswordField, validators

class RegisterForm(Form):
    name = StringField('Full Name', [validators.Length(min=1,max=50)])
    username = StringField('Username', [validators.Length(min=4,max=25)])
    email = StringField('Email', [validators.Length(min=6,max=100)])
    instansi = StringField('Email', [validators.Length(min=6,max=50)])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')
    
class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])


# class UploadDocumentForm(Form):
#     project_name = StringField('projectName', [validators.Length(min=1,max=100)])
#     document_name = StringField('documentName', [validators.Length(min=4,max=25)])
#     document = StringField('document')