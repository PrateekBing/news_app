from flask import Flask, render_template, url_for, redirect
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from newsapi import NewsApiClient
import requests

app = Flask(__name__)
newsapi = NewsApiClient(api_key='551c5fa6a12d40b78a93259b3a488ed0')
app.config['SECRET_KEY'] = 'itisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=False)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=17)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return render_template('error.html')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return render_template('newuser.html')
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    name = current_user.username


    khabar = newsapi.get_top_headlines(language='en', country='in')
    articles = khabar['articles']

    desc = []
    news = []
    img = []
    url = []


    for i in range(len(articles)):
        myarticles = articles[i]

        news.append(myarticles['title'])
        desc.append(myarticles['description'])
        img.append(myarticles['urlToImage'])
        url.append(myarticles['url'])
        


    mylist = zip(news, desc, img, url)



    return render_template('dashboard.html', name=name, khabar=khabar, articles=articles, context=mylist, url=url)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('login')

@app.route('/delete', methods=['POST'])
@login_required
def delete():
    current_user.delete()
    return redirect('login')

if __name__ == '__main__':
    app.run(debug=True)
