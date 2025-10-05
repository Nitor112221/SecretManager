import sys

import flask

from blueprints import api
from blueprints import api_master_password
from db_manager import DatabaseManager

app = flask.Flask(__name__)
app.register_blueprint(api.api)
app.register_blueprint(api_master_password.api_master)

if __name__ == '__main__':
    db = DatabaseManager('data/database.db')

    port = 5678

    if len(sys.argv) == 2:
        port = int(sys.argv[1])

    app.run(host='127.0.0.1', port=port)

