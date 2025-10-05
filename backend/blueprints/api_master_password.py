import http

import flask
from flask import Blueprint, abort, request

from crypts.tools import check_exist_master_password, hash_password

api_master = Blueprint('api_master', __name__)


@api_master.route('/master_password_exist', methods=['GET'])
def master_password_exist():
    if check_exist_master_password():
        return flask.Response(status=http.HTTPStatus.OK)

    return abort(http.HTTPStatus.NOT_FOUND)


@api_master.route('/set_master_password', methods=['POST'])
def set_master_password():
    if 'password' not in request.json \
            or not isinstance(request.json['password'], str):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if check_exist_master_password():
        return abort(http.HTTPStatus.BAD_REQUEST)

    with open('data/master_password.txt', 'w') as file:
        file.write(hash_password(request.json['password']))

    return flask.Response(status=http.HTTPStatus.CREATED)