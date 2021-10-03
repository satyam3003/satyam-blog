from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, EqualTo, InputRequired
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegistrationForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password",
                             validators=[InputRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField("Repeat Password")
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password",
                             validators=[InputRequired()])
    submit = SubmitField("Let me in")

class CommentForm(FlaskForm):
    comment = CKEditorField("Add Comment", validators=[DataRequired()])
    submit = SubmitField("Add comment")


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email Address", validators=[DataRequired(), Email()])
    phone = StringField("Phone Number")
    message = StringField("message", validators=[DataRequired()])
    submit = SubmitField("Send")



