import flask

from db_manager import DatabaseManager

app = flask.Flask(__name__)

DatabaseManager().connect('data/database.db')
