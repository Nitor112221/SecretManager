import http

import flask
from flask import Blueprint, jsonify, abort
from flask import request

from backend.db_manager import DatabaseManager
from backend.crypts.tools import check_exist_master_password, compare_hash_password, encrypt_string, decrypt_string

api = Blueprint('api', __name__)


@api.before_request
def middleware_check_exist_master_password():
    if not check_exist_master_password():
        return abort(http.HTTPStatus.INTERNAL_SERVER_ERROR)


@api.route('/find_by_name', methods=['GET'])
def find_by_name():
    if 'name' not in request.args:
        return abort(http.HTTPStatus.BAD_REQUEST)

    data = DatabaseManager().get_secrets_by_substring(request.args['name'])

    if data is None:
        return jsonify({'status': 'Not found', 'data': []}), http.HTTPStatus.OK

    secrets = []
    for i in data:
        secrets.append({'name': i[1], 'id': i[0]})
    return jsonify({'status': 'Found', 'data': secrets}), http.HTTPStatus.OK


@api.route('/create_secret', methods=['POST'])
def create_secret():
    # проверка корректности присланных данных
    if 'name' not in request.json \
            or not isinstance(request.json['name'], str):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if 'data' not in request.json \
            or not isinstance(request.json['data'], list):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if 'password' not in request.json \
            or not isinstance(request.json['password'], str):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if compare_hash_password(request.json['password']):
        return abort(http.HTTPStatus.FORBIDDEN)

    fields = []

    for secret_fields in request.json['data']:
        if not isinstance(secret_fields, dict) \
                or 'label' not in secret_fields \
                or 'value' not in secret_fields:
            return abort(http.HTTPStatus.BAD_REQUEST)
        fields.append({'label': secret_fields['label'],
                       'value': encrypt_string(request.json['password'], secret_fields['value'])})

    result = DatabaseManager().create_secret(request.json['name'], fields)
    if result:
        return flask.Response(status=http.HTTPStatus.CREATED)

    return abort(http.HTTPStatus.BAD_REQUEST)


@api.route('/get_secret', methods=["POST"])
def get_secret():
    if 'id' not in request.json \
            or isinstance(request.json['id'], int):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if 'password' not in request.json \
            or isinstance(request.json['password'], str):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if not compare_hash_password(request.json['password']):
        return abort(http.HTTPStatus.FORBIDDEN)

    fields = DatabaseManager().get_fields_of_secret(request.json['id'])

    if fields is None:
        return abort(http.HTTPStatus.NOT_FOUND)

    response = []

    for field in fields:
        response.append({'label': field['label'], 'value': decrypt_string(request.json['password'], fields['value'])})

    return jsonify(response), http.HTTPStatus.OK


@api.route('/delete_secret', methods=["DELETE"])
def delete_secret():
    if 'id' not in request.json \
            or isinstance(request.json['id'], int):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if 'password' not in request.json \
            or isinstance(request.json['password'], str):
        return abort(http.HTTPStatus.BAD_REQUEST)

    if not compare_hash_password(request.json['password']):
        return abort(http.HTTPStatus.FORBIDDEN)

    secret = DatabaseManager().get_secret_by_id(request.json['id'])
    if secret is None:
        return abort(http.HTTPStatus.NOT_FOUND)

    DatabaseManager().delete_secret(request.json['id'])

    return flask.Response(status=http.HTTPStatus.OK)
