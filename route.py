import os
import pathlib
import requests
from flask import Blueprint, render_template, flash, url_for, session, abort, redirect, request,Flask
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from __init__ import db   
from flask_login import login_user, login_required, logout_user, current_user
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import random
import string
from pip._vendor import cachecontrol
from flask_migrate import Migrate

app = Flask(__name__)

web = Blueprint('web', __name__)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
app.secret_key = 'efdgdrgersdgrsgf rsdgfrsgg'
migrate = Migrate(app, db)


client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret_755821205792-00ql277l4se0f346s77796sd8qb816j5.apps.googleusercontent.com.json")


GOOGLE_CLIENT_ID = "755821205792-00ql277l4se0f346s77796sd8qb816j5.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"



flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback",
)

@web.route('/', methods=['GET', 'POST'])
@login_required

def home():

  return render_template('home.html',user=current_user)
   
@web.route('/login')
def login_page():

  return render_template('login.html')


@web.route('/loginbygoogle')
def login_bygoogle():

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)



@web.route('/callback')
def callback():



    flow.fetch_token(authorization_response=request.url)



    if not session["state"] == request.args["state"]:
        abort(500)  



    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
        
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        plain_password = ''.join(random.choice(string.ascii_letters) for i in range(10))
        hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256')



        new_user = User(
            email=session["email"],
            first_name=session["name"],
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    flash('Logged in successfully!', category='success')
    login_user(user, remember=True)
    return redirect(url_for('web.home'))



@web.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('web.login_page'))



@web.route("/about")
def about():
    return render_template("about.html",user=current_user)


@web.route('/share_on_whatsapp')
def share_on_whatsapp():
    text_to_share = "This is a Flask app with Google Auth, and you can share this on WhatsApp!"
    url_to_share = request.args.get('url', 'http://127.0.0.1:5000')
    whatsapp_url = f"https://wa.me/?text={urllib.parse.quote_plus(f'{text_to_share} {url_to_share}')}"
    return render_template('share_template.html', link=whatsapp_url)