from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Setup MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client.user_database
users = db.users

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    user = users.find_one({"_id": user_id})
    if user:
        return User(user_id=user['_id'])
    return None
class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users.insert_one({"_id": email, "password": hashed_pw})
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = users.find_one({"_id": email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            login_user(User(user_id=user['_id']))
            return redirect(url_for('dashboard'))
        flash('Login Unsuccessful. Please check your email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello Geeks, {current_user.id}!'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True)