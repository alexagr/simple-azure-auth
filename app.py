from flask import Flask, render_template, session, request, redirect, url_for
from simple_azure_auth import AzureAuth
import app_config


app = Flask(__name__)
app.secret_key = b'8_$K"F6Qxz\n\xec79]/'
app.config.from_object(app_config)

azure_auth = AzureAuth(app_config.CLIENT_ID, app_config.TENANT_ID, app_config.MULTI_TENANT)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/1.0.x/deploying/wsgi-standalone/#proxy-setups
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


@app.route("/")
def index():
    print(session)
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template('index.html', user=session["user"], logout_url=url_for("logout", _external=True))


@app.route("/login")
def login():
    data = azure_auth.build_auth_url(redirect_url=url_for("get_token", _external=True))
    session["nonce"] = data["nonce"]
    print(data)
    return render_template("login.html", auth_url=data["auth_url"])


@app.route(app_config.REDIRECT_PATH, methods=['POST'])
def get_token():
    id_token = request.form.get('id_token', '')
    data = azure_auth.parse_token(id_token, audience=app_config.CLIENT_ID, nonce=session.get('nonce', ''))
    if "error" in data:
        return render_template("failed.html", error=data["error"])

    if app_config.USER_ROLE and not azure_auth.check_role(data, app_config.USER_ROLE):
        return render_template("failed.html", error="User is not granted '{}' role".format(app_config.USER_ROLE))

    session["user"] = data["payload"].get('name', '') or data["payload"].get('preferred_username', '')
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(azure_auth.build_logout_url(url_for("index", _external=True)))


if __name__ == "__main__":
    app.run()

