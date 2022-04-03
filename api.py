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


class ValidationError(Exception):
    pass


class BaseField(ABC):

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    @abstractmethod
    def valid(self, value):
        if (value is None) and self.required:
            raise ValidationError(f'Поле должно быть обязательным;')

        if (not value) and not self.nullable:
            raise ValidationError(f'Поле не может быть пустым;')


class CharField(BaseField):
    def valid(self, value):
        super().valid(value)
        if value and not isinstance(value, str):
            raise ValidationError(f'поле должно быть строкой;')


class ArgumentsField(BaseField):
    def valid(self, value):
        super().valid(value)
        if not isinstance(value, dict):
            raise ValidationError(f'поле должно быть словарем;')


class EmailField(CharField):
    def valid(self, value):
        super().valid(value)
        if value and ('@' not in value):
            raise ValidationError(f'поле должно быть почтовым адресом;')


class PhoneField(BaseField):
    def valid(self, value):
        super().valid(value)
        if value is None:
            return

        if not isinstance(value, (str, int)):
            raise ValidationError(f'поле должно быть строкой или числом;')

        if len(str(value)) != 11:
            raise ValidationError(f'поле должен содержать 11 символов;')
        if not str(value).startswith('7'):
            raise ValidationError(f'поле должно начинатьс с цифры "7";')


class DateField(BaseField):
    def valid(self, value):
        super().valid(value)
        if value:
            try:
                datetime.datetime.strptime(value, '%d.%m.%Y')
            except ValueError:
                raise ValidationError(f'поле должно быть в формате "DD.MM.YYYY";')


class BirthDayField(DateField):
    def valid(self, value):
        super().valid(value)
        if value:
            try:
                if datetime.datetime.now().year - datetime.datetime.strptime(value, '%d.%m.%Y').year > 70:
                    raise ValidationError(f'поле должно быть не старше 70 лет;')
            except ValueError:
                pass


class GenderField(BaseField):
    def valid(self, value):
        super().valid(value)
        if value and value not in [0, 1, 2]:
            raise ValidationError(f'поле должно содержать одно из значений [0, 1, 2];')


class ClientIDsField(BaseField):
    def valid(self, value):
        super().valid(value)
        if not isinstance(value, list):
            raise ValidationError(f'поле должно быть массивом;')
        else:
            if not all([isinstance(i, int) for i in value]):
                raise ValidationError(f'поле массив должен состоять из чисел;')


class RequestMeta(type):
    """у создаваемого класса убираем все дескрипторы в отдельный словарь "fields" """
    def __new__(mcl, name, bases, attrs):
        fields = {}
        for key, value in list(attrs.items()):
            if isinstance(value, BaseField):
                fields[key] = attrs.pop(key)
        attrs['fields'] = fields
        return super().__new__(mcl, name, bases, attrs)


class BaseRequest(metaclass=RequestMeta):
    def __init__(self, request_fields=None):
        self.request_fields = request_fields
        self.err_msg = ''

    def __getattr__(self, item):
        return self.request_fields.get(item) or ''

    def is_valid(self):
        return all(self.field_is_correct(fn, fo) for fn, fo in self.fields.items())

    def field_is_correct(self, field_name, field_obj):
        value = self.request_fields.get(field_name)
        try:
            field_obj.valid(value)
            return True
        except ValidationError as err:
            msg = f'Поле "{field_name}" со значением "{value}", не валидно({err})\n'
            self.err_msg += msg
            logging.error(msg)
            return False


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def set_context(self, ctx):
        ctx['nclients'] = len(self.client_ids)

    def get_answer(self, store):
        answer = {}
        for cid in self.client_ids:
            answer[cid] = get_interests(store, cid)
        return answer


class OnlineScoreRequest(BaseRequest):
    phone = PhoneField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def is_valid(self):
        return super().is_valid() and self.valid_pair_fields()

    def set_context(self, ctx):
        has = [field for field in self.fields if self.request_fields.get(field) is not None]
        logging.info(f'Получены поля {has}')
        ctx['has'] = has

    def valid_pair_fields(self):
        for field1, field2 in [("phone", "email"),
                               ("first_name", "last_name"),
                               ("gender", "birthday")]:
            if self.request_fields.get(field1) is not None and self.request_fields.get(field2) is not None:
                return True

        self.err_msg += f'Парные поля не валидны\n'

    def get_answer(self, store):
        return {'score': get_score(
            store=store,
            phone=self.phone,
            email=self.email,
            birthday=self.birthday,
            gender=self.gender,
            first_name=self.first_name,
            last_name=self.last_name)}


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode()).hexdigest()

    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    methods = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest, }

    body, headers = request['body'], request['headers']
    mr = MethodRequest(body)
    if not mr.is_valid():
        return mr.err_msg, INVALID_REQUEST

    if not check_auth(mr):
        logging.info('Bad auth')
        return ERRORS[FORBIDDEN], FORBIDDEN

    method = methods[body['method']](request_fields=body['arguments'])

    if not method.is_valid():
        return method.err_msg, INVALID_REQUEST

    if mr.is_admin:
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
