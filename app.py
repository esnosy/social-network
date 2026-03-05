import hashlib
import logging
import os
import secrets
import datetime
from math import ceil

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    abort
)
from pymongo import MongoClient
from flask_session import Session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


load_dotenv(".env.local")

mongo = MongoClient(os.environ["MONGODB_URI"])

app = Flask(__name__)
app.config["SESSION_TYPE"] = "mongodb"
app.config["SESSION_MONGODB"] = mongo
Session(app)


@app.get("/profile/<username>")
def profile(username: str):
    signed_in_username = session.get("username")
    if signed_in_username is None:
        return redirect("/signin")
    user = mongo.users.users.find_one({"name": username})
    if user is None:
        return abort(404)

    page = request.args.get("page", 1, type=int)
    page_size = 10

    posts_agg = list(mongo.posts.posts.aggregate(
        [
            {"$match": {"username": username}},
            # Sort from newest to oldest
            {"$sort": {"timestamp": -1}},
            {
                "$facet": {
                    "metadata": [{"$count": "totalCount"}],
                    "data": [{"$skip": (page - 1) * page_size}, {"$limit": page_size}],
                },
            },
        ]
    ))
    posts = posts_agg[0]["data"]
    total_count = posts_agg[0]["metadata"][0]["totalCount"]
    total_pages = ceil(total_count / page_size)
    is_last = page == total_pages
    is_first = page == 1
    return render_template(
        "profile.html", username=username, posts=posts, is_last=is_last, is_first=is_first
    )


@app.post("/post")
def post():
    username = session.get("username")
    if username is None:
        return redirect("/signin")
    text = request.form.get("post")
    collection = mongo.posts.posts
    collection.insert_one(
        {
            "username": username,
            "text": text,
            "timestamp": datetime.datetime.now(tz=datetime.timezone.utc),
        }
    )
    return redirect("/")


@app.route("/")
def index():
    username = session.get("username")
    if username is None:
        return redirect("/signin")

    page = request.args.get("page", 1, type=int)
    page_size = 10

    # https://codebeyondlimits.com/articles/pagination-in-mongodb-the-only-right-way-to-implement-it-and-avoid-common-mistakes
    posts_agg = list(mongo.posts.posts.aggregate(
        [
            # Sort from newest to oldest
            {"$sort": {"timestamp": -1}},
            {
                "$facet": {
                    "metadata": [{"$count": "totalCount"}],
                    "data": [{"$skip": (page - 1) * page_size}, {"$limit": page_size}],
                },
            },
        ]
    ))
    posts = posts_agg[0]["data"]
    total_count = posts_agg[0]["metadata"][0]["totalCount"]
    total_pages = ceil(total_count / page_size)
    is_last = page == total_pages
    is_first = page == 1
    return render_template(
        "index.html", username=username, posts=posts, is_last=is_last, is_first=is_first
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    username = session.get("username")
    if username:
        return redirect("/")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or len(username) < 8:
            flash("Please provide username of at least length 8")
            return render_template("signup.html", username=username, password=password)

        db = mongo.users
        c = db.users.count_documents({"name": username})
        if c > 0:
            flash("User already exists, choose a different user name")
            return render_template("signup.html", username=username, password=password)

        if not password or len(password) < 8:
            flash("Please provide password of at least length 8")
            return render_template("signup.html", username=username, password=password)

        salt = secrets.token_hex(nbytes=16)
        salted_password = password + salt
        password_hash = hashlib.sha256(
            salted_password.encode("utf-8")).hexdigest()
        db.users.insert_one(
            {"name": username, "password_hash": password_hash, "salt": salt}
        )
        session["username"] = username
        return redirect("/")
    return render_template("signup.html")


@app.route("/signin", methods=["GET", "POST"])
def signin():
    username = session.get("username")
    if username:
        return redirect("/")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or len(username) < 8:
            flash("Please provide username of at least length 8")
            return render_template("signin.html", username=username, password=password)

        if not password or len(password) < 8:
            flash("Please provide password of at least length 8")
            return render_template("signin.html", username=username, password=password)
        db = mongo.users
        user = db.users.find_one({"name": username})
        if user is None:
            flash("User not found")
            return render_template("signin.html", username=username, password=password)
        salt = user["salt"]
        db_password_hash = user["password_hash"]
        salted_password = password + salt
        password_hash = hashlib.sha256(
            salted_password.encode("utf-8")).hexdigest()
        if db_password_hash == password_hash:
            session["username"] = username
            return redirect("/")
        else:
            flash("Wrong password")
            return render_template("signin.html", username=username, password=password)

    return render_template("signin.html")


@app.route("/signout")
def signout():
    session.clear()
    return redirect("/signin")
