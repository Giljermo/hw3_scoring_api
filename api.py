#!/usr/bin/env python
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler

from scoring import get_score, get_interests

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


class BaseField(ABC):

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    def __set_name__(self, owner, name):
        self.public_name = name
        self.private_name = '_' + name

    def __get__(self, instance, cls):
        return getattr(instance, self.private_name)

    def __set__(self, obj, value):
        val = value.get(self.public_name)
        self.validate(val, obj)
        setattr(obj, self.private_name, val)

    @abstractmethod
    def validate(self, value, obj):
        if (value is None) and self.required:
            obj.error_messages += f'поле "{self.public_name}" должно быть обязательным; '

        if (not value) and not self.nullable:
            obj.error_messages += f'поле "{self.public_name}" не может быть пустым; '


class CharField(BaseField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if value and not isinstance(value, str):
            obj.error_messages += f'поле "{self.public_name}" должно быть строкой; '


class ArgumentsField(BaseField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if not isinstance(value, dict):
            obj.error_messages += f'поле "{self.public_name}" должно быть словарем; '


class EmailField(CharField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if value and ('@' not in value):
            obj.error_messages += f'поле "{self.public_name}" должно быть почтовым адресом; '


class PhoneField(BaseField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if value is None:
            return

        if not isinstance(value, (str, int)):
            obj.error_messages += f'поле "{self.public_name}" должно быть строкой или числом; '

        if len(str(value)) != 11:
            obj.error_messages += f'поле "{self.public_name}" должен содержать 11 символов; '
        if not str(value).startswith('7'):
            obj.error_messages += f'поле "{self.public_name}" должно начинатьс с цифры "7"; '


class DateField(BaseField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if value:
            try:
                datetime.datetime.strptime(value, '%d.%m.%Y')
            except ValueError:
                obj.error_messages += f'поле "{self.public_name}" должно быть в формате "DD.MM.YYYY"; '


class BirthDayField(CharField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if value:
            try:
                bd = datetime.datetime.strptime(value, '%d.%m.%Y')
            except ValueError:
                obj.error_messages += f'поле "{self.public_name}" должно быть в формате "DD.MM.YYYY"; '
            else:
                if datetime.datetime.now().year - bd.year > 70:
                    obj.error_messages += f'поле "{self.public_name}" должно быть не старше 70 лет; '


class GenderField(BaseField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if value and value not in [0, 1, 2]:
            obj.error_messages += f'поле "{self.public_name}" должно содержать одно из значений [0, 1, 2]; '


class ClientIDsField(BaseField):
    def validate(self, value, obj):
        super().validate(value, obj)
        if not isinstance(value, list):
            obj.error_messages += f'поле "{self.public_name}" должно быть массивом; '
        else:
            if not all([isinstance(i, int) for i in value]):
                obj.error_messages += f'поле "{self.public_name}" массив должен состоять из чисел; '


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    phone = PhoneField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class ValidatorMethodRequest(MethodRequest):
    def __init__(self, body):
        self.error_messages = ''
        self.account = body
        self.login = body
        self.token = body
        self.arguments = body
        self.method = body


class ValidatorOnlineScoreRequest(OnlineScoreRequest):
    def __init__(self, arguments):
        self.error_messages = ''
        self.phone = arguments
        self.email = arguments
        self.first_name = arguments
        self.last_name = arguments
        self.birthday = arguments
        self.gender = arguments

    def validate(self):
        if not ((self.phone and self.email) or
                (self.first_name and self.last_name) or
                ((self.gender is not None) and self.birthday)):
            self.error_messages += 'должна присутсвует хоть одна пара ' \
                                   '"phone-email, first name-last name, gender-birthday" с непустыми значениями'

    def set_context(self, ctx):
        has = []
        if self.phone:
            has.append('phone')
        if self.email:
            has.append('email')
        if self.first_name:
            has.append('first_name')
        if self.last_name:
            has.append('last_name')
        if self.birthday:
            has.append('birthday')
        if self.gender is not None:
            has.append('gender')

        ctx['has'] = has

    def get_answer(self, store):
        return {'score': get_score(
            store=store,
            phone=self.phone,
            email=self.email,
            birthday=self.birthday,
            gender=self.gender,
            first_name=self.first_name,
            last_name=self.last_name)}


class ValidatorClientsInterestsRequest(ClientsInterestsRequest):
    def __init__(self, arguments):
        self.error_messages = ''
        self.client_ids = arguments
        self.date = arguments

    def validate(self):
        pass

    def set_context(self, ctx):
        ctx['nclients'] = len(self.client_ids)

    def get_answer(self, store):
        answer = {}
        for cid in self.client_ids:
            answer[cid] = get_interests(store, cid)
        return answer


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode()).hexdigest()

    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    body, headers = request['body'], request['headers']
    methods = {
        'online_score': ValidatorOnlineScoreRequest,
        'clients_interests': ValidatorClientsInterestsRequest,
    }

    vmr = ValidatorMethodRequest(body)
    if vmr.error_messages:
        return vmr.error_messages, INVALID_REQUEST

    if not check_auth(vmr):
        logging.info('Bad auth')
        return ERRORS[FORBIDDEN], FORBIDDEN

    method = methods[body['method']](arguments=body['arguments'])
    method.validate()

    if method.error_messages:
        return method.error_messages, INVALID_REQUEST

    if vmr.is_admin:
        return {'score': 42}, OK

    method.set_context(ctx)
    return method.get_answer(store), OK


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
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

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
        self.wfile.write(json.dumps(r))
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
