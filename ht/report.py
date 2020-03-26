#! /usr/bin/env python

from flask import Flask, redirect, url_for, request, render_template
import flask_login
import sqlite3

sql_db = '/home/jtye/tt/db/tt.db'

app = Flask(__name__)
app.secret_key = 'ekyfvfFYZVAWm6dx4Gy5TEs8av2WLKDQB9mdeqGaGGLb9yzh2WsM8nhknBHLHnHxrCqxw9PMw8pph8BsMCmPmuqQXPzRE7XZNqAcnrz5rfCqbvY5aMjJRdGk'

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

users = {'admin': {'password': 'password'}}

class User(flask_login.UserMixin):
    pass

@app.route('/')
def index():
    return '''<a href="/login">login</a>'''

@app.route('/devices')
def devices():
    with sqlite3.connect(sql_db) as con:
        cur = con.cursor()
        cur.execute("select * from tt_devicelist")
        rows = cur.fetchall()
        return render_template("devices.html", rows = rows)

@app.route('/devices/ip/<ip>')
def ip_dev(ip):
     with sqlite3.connect(sql_db) as con:
         cur = con.cursor()
         sql_q = "select * from tt_log where ip_src = '" + ip + "'"
         cur.execute(sql_q)
         rows = cur.fetchall()
         return render_template("ip.html", rows = rows)


@app.route('/devices/<dev>')
def ether_dev(dev):
    with sqlite3.connect(sql_db) as con:
        cur = con.cursor()
        sql_q = "select * from tt_log where ether_src = '" + dev + "'"
        cur.execute(sql_q)
        rows = cur.fetchall()
        return render_template("ether.html", rows = rows)

@app.route('/reports')
def reports():
    with sqlite3.connect(sql_db) as con:
        cur = con.cursor()
        cur.execute("select * from tt_report")
        rows = cur.fetchall()
        return render_template("report.html", rows = rows)

@app.route('/reports/<inc>')
def incident(inc):
    with sqlite3.connect(sql_db) as con:
        cur = con.cursor()
        sql_q = "select * from tt_log where incident_id = " + inc + " and read = 'read'"
        cur.execute(sql_q)
        rows = cur.fetchall()
        return render_template("incident.html", rows = rows)

@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return
    user = User()
    user.id = username
    return user

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    if username not in users:
        return
    user = User()
    user.id = username
    user.is_authenticated = request.form['password'] == users[username]['password']

    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '''
               <form action='login' method='POST'>
                <input type='text' name='username' id='username' placeholder='username'/>
                <input type='password' name='password' id='password' placeholder='password'/>
                <input type='submit' name='submit'/>
               </form>
               '''

    username = request.form['username']
    if request.form['password'] == users[username]['password']:
        user = User()
        user.id = username
        flask_login.login_user(user)
        return redirect(url_for('protected'))

    return 'Bad login'

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return 'Logged out'

@app.route('/protected')
@flask_login.login_required
def protected():
    ret = 'Logged in as: ' + flask_login.current_user.id + '''<br><a href="/reports">Reports</a>'''
    return ret


@login_manager.unauthorized_handler
def unauthorized_handler():
        return 'Unauthorized'

if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port='80')
