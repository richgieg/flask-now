from datetime import datetime

from flask import flash, Flask, redirect, render_template, session, url_for
from flask.ext.bootstrap import Bootstrap
from flask.ext.moment import Moment
from flask.ext.script import Manager
from flask.ext.wtf import Form

app = Flask(__name__)
app.secret_key = 'change me before production'

bootstrap = Bootstrap(app)
manager = Manager(app)
moment = Moment(app)


@app.route('/')
def index():
    return render_template('index.html', current_time=datetime.utcnow())


if __name__ == '__main__':
    manager.run()
