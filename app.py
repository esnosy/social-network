import hashlib
import logging
import os
import secrets
import datetime
from math import ceil

from supabase import create_client, Client
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, abort

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


load_dotenv(".env")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "")

supabase: Client = create_client(
    os.environ.get("SUPABASE_URL", ""),
    os.environ.get("SUPABASE_KEY", ""),
)


@app.get("/profile/<username>")
def profile(username: str):
    signed_in_username = session.get("username")
    if signed_in_username is None:
        return redirect("/signin")
    res = supabase.table("users").select("*").eq("name", username).execute()
    if len(res.data) == 0:
        return abort(404)

    page = request.args.get("page", 1, type=int)
    page_size = 10

    start = (page - 1) * page_size
    end = start + page_size - 1  # Supabase range is inclusive

    res = (
        supabase.table("users").select("*, posts(count)").eq("name", username).execute()
    )
    total_count = res.data[0]["posts"][0]["count"]
    if total_count == 0:
        posts = []
    else:
        res = (
            supabase.table("posts")
            .select("*")
            .eq("user_id", session["user_id"])
            .order("created_at", desc=True)
            .range(start, end)
            .execute()
        )
        posts = res.data
    total_pages = ceil(total_count / page_size)
    is_last = page == total_pages or total_count == 0
    is_first = page == 1
    return render_template(
        "profile.html",
        username=username,
        posts=posts,
        is_last=is_last,
        is_first=is_first,
    )


@app.post("/post")
def post():
    username = session.get("username")
    if username is None:
        return redirect("/signin")
    text = request.form.get("post")
    supabase.table("posts").insert(
        {"user_id": session["user_id"], "text": text}
    ).execute()
    return redirect("/")


@app.route("/")
def index():
    username = session.get("username")
    if username is None:
        return redirect("/signin")

    page = request.args.get("page", 1, type=int)
    page_size = 10

    start = (page - 1) * page_size
    end = start + page_size - 1  # Supabase range is inclusive

    res = supabase.table("posts").select("*", count="exact", head=True).execute()
    total_count = res.count

    if total_count == 0:
        posts = []
    else:
        res = (
            supabase.table("posts")
            .select("*, users(name)")
            .order("created_at", desc=True)
            .range(start, end)
            .execute()
        )
        posts = res.data

    total_pages = ceil(total_count / page_size)
    is_last = page == total_pages or total_count == 0
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
        if not username:
            flash("Please provide username")
            return render_template("signup.html", username=username, password=password)

        res = supabase.table("users").select("*").eq("name", username).execute()
        if len(res.data) > 0:
            flash("User already exists, choose a different user name")
            return render_template("signup.html", username=username, password=password)

        if not password or len(password) < 8:
            flash("Please provide password of at least length 8")
            return render_template("signup.html", username=username, password=password)

        salt = secrets.token_hex(nbytes=16)
        salted_password = password + salt
        password_hash = hashlib.sha256(salted_password.encode("utf-8")).hexdigest()
        res = (
            supabase.table("users")
            .insert({"name": username, "password_hash": password_hash, "salt": salt})
            .execute()
        )
        session["username"] = username
        session["user_id"] = res.data[0]["id"]
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
        if not username:
            flash("Please provide username")
            return render_template("signin.html", username=username, password=password)

        if not password or len(password) < 8:
            flash("Please provide password of at least length 8")
            return render_template("signin.html", username=username, password=password)
        res = supabase.table("users").select("*").eq("name", username).execute()
        if len(res.data) == 0:
            flash("User not found")
            return render_template("signin.html", username=username, password=password)
        db_salt = res.data[0]["salt"]
        db_password_hash = res.data[0]["password_hash"]
        salted_password = password + db_salt
        password_hash = hashlib.sha256(salted_password.encode("utf-8")).hexdigest()
        if db_password_hash == password_hash:
            session["username"] = username
            session["user_id"] = res.data[0]["id"]
            return redirect("/")
        else:
            flash("Wrong password")
            return render_template("signin.html", username=username, password=password)

    return render_template("signin.html")


@app.route("/signout")
def signout():
    session.clear()
    return redirect("/signin")


if __name__ == "__main__":
    app.run(debug=True)
