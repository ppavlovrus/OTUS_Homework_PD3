#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import re
import json
import datetime
import logging
import hashlib
import uuid
from datetime import datetime, timedelta
from optparse import OptionParser
from scoring import get_score, get_interests
from http.server import BaseHTTPRequestHandler, HTTPServer

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

class Field:
    def __init__(self, value, required=True, nullable=True):
        self.required = required
        self.nullable = nullable
        self._value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        self.validate(val)
        self._value = val

    def validate(self, value):
        if self.required and not value:
            raise ValueError("Value cannot be empty.")


class CharField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, str):
            raise ValueError("Value must be a string.")



class ArgumentsField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, dict):
            raise ValueError("Value must be a dictionary.")

class EmailField(CharField):
    def validate(self, value):
        super().validate(value)
        if "@" not in value:
            raise ValueError("Value must be a valid email address.")


class PhoneField(Field):
    def validate(self, value):
        super().validate(value)
        if not re.match(r'^(\+\d{1,3}[- ]?)?\d{10}$', value):
            raise ValueError("Invalid phone number.")


class DateField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, datetime.date):
            raise ValueError("Value must be a datetime.date instance.")

class BirthDayField(DateField):
    def validate(self, value):
        super().validate(value)
        handred_years_ago = datetime.now() - timedelta(days=100 * 365.25)
        if value >= handred_years_ago:
            raise ValueError("Birthdate value more then 100 years ago.")



class GenderField(Field):
    def validate(self, value):
        super().validate(value)
        if value not in (1,2):
            raise ValueError("Invalid gender.")



class ClientIDsField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, list):
            raise ValueError("Value must be a list.")

class ClientsInterestsRequest(object):
    def __init__(self,arguments_dictionary):
        self.client_ids = ClientIDsField(arguments_dictionary["client_ids"], required=True)
        self.date = DateField(arguments_dictionary["date"], required=False, nullable=True)
    def validate(self):
        if self.client_ids.value and self.date.value:
            return True
        else:
            return False

    def return_response(self):
        interests = get_interests("", self.client_ids.value)
        return f"{{ {interests} }}"

class OnlineScoreRequest(object):
    def __init__(self,arguments_dictionary):
        self.first_name = CharField(arguments_dictionary["first_name"],required=False, nullable=True)
        self.last_name = CharField(arguments_dictionary["last_name"],required=False, nullable=True)
        self.email = EmailField(arguments_dictionary["email"],required=False, nullable=True)
        self.phone = PhoneField(arguments_dictionary["phone"],required=False, nullable=True)
        self.birthday = BirthDayField(arguments_dictionary["birthday"], required=False, nullable=True)
        self.gender = GenderField(arguments_dictionary["gender"], required=False, nullable=True)
    def validate(self):
        name_check = self.first_name.value and self.last_name.value
        contact_check = self.email.value and self.phone.value
        personal_info_check = self.gender.value and self.birthday.value

        if name_check or contact_check or personal_info_check:
            return True
        else:
            return False
    def get_score(self):
        if self.first_name is "admin":
            return 42
        else:
            return get_score("", self.phone.value,self.email.value,
                             self.birthday.value,self.gender.value,
                             self.first_name.value, self.last_name.value)
    def return_response(self):
        return self.get_score()

class MethodRequest(object):
    def __init__(self, request):

        self.account = CharField(request.get("account"), required=False, nullable=True)
        self.login = CharField(request.get("login"), required=True, nullable=True)
        self.token = CharField(request.get("token"), required=True, nullable=True)
        self.arguments = ArgumentsField(request.get("arguments"), required=True, nullable=True)
        self.method = CharField(request.get("method"), required=True, nullable=False)
    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

def check_auth(request):

    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512((
            request.account.value + request.login.value + SALT).encode('utf-8')).hexdigest()
    if digest == request.token.value:
        return True
    return False


def method_handler(request, ctx, store):
    methods = {
        "online_score": OnlineScoreRequest,
        "clients_interests": ClientsInterestsRequest
    }

    method_request = MethodRequest(request["body"])
    if not check_auth(method_request):
        return None, FORBIDDEN
    if method_request.method.value not in methods.keys():
        raise ValueError("Invalid method")
    current_method_class = methods[method_request.method.value]
    current_method = current_method_class(method_request.arguments.value)
    if current_method.validate():
        response = current_method.return_response()
        code = OK
    else:
        response = "BAD RESPONSE"
        code = BAD_REQUEST
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            lenght = int(self.headers['Content-Length'])
            data_string = self.rfile.read(lenght)
            request = json.loads(data_string)
        except (ValueError, TypeError) as e:
            code = BAD_REQUEST
            logging.error(f"Exception received. Details {e}")


        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
