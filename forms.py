from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,BooleanField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    name= StringField("Name of Product", validators=[DataRequired()])
    price = StringField("Price", validators=[DataRequired()])
    img_url = StringField("Product Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Description", validators=[DataRequired()])
    submit = SubmitField("Submit Product")
class CreateSalesForm(FlaskForm):
    name= StringField("Name of Product", validators=[DataRequired()])
    old_price = StringField("Old Price", validators=[DataRequired()])
    new_price = StringField("New Price", validators=[DataRequired()])
    img_url = StringField("Product Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Description", validators=[DataRequired()])
    submit = SubmitField("Submit Product")

class RegisterForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    Submit = SubmitField(label="Register")

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    Submit = SubmitField(label="Let Me In")


class CommentForm(FlaskForm):
    comment = CKEditorField("Review", validators=[DataRequired()])
    Submit = SubmitField(label="Submit review")