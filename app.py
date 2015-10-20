from flask import flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.script import Manager

app = Flask(__name__)
bootstrap = Bootstrap(app)
manager = Manager(app)


app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    manager.run()
