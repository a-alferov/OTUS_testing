#!/usr/bin/env python

from http.server import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser
from weakref import WeakKeyDictionary
import re
import json
import uuid
import hashlib
import logging
import datetime

from scoring import get_interests, get_score

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
    def __init__(self, required: bool = False, nullable: bool = False):
        self.required = required
        self.nullable = nullable
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner) -> str:
        return self.data.get(instance)

    def __set__(self, instance, value) -> None:
        if self.required and value is None:
            raise ValueError(f"Field {self.__class__.__name__} is required")
        if not self.nullable and value is None:
            raise ValueError(f"Field {self.__class__.__name__} is not nullable")

        self.validate(value=value)
        self.data[instance] = value

    def validate(self, value) -> None:
        ...


class CharField(Field):
    def validate(self, value) -> None:
        if value and not isinstance(value, str):
            raise ValueError("Must be a string")


class ArgumentsField(Field):
    def validate(self, value) -> None:
        if value and not isinstance(value, dict):
            raise ValueError("Must be a dictionary")


class EmailField(CharField):
    def validate(self, value) -> None:
        super().validate(value=value)

        if value and "@" not in value:
            raise ValueError("Must be a valid email address")


class PhoneField(Field):
    def validate(self, value) -> None:
        if not value:
            return

        if not isinstance(value, (int, str)):
            raise TypeError("Must be a string or an integer")

        if not re.match(r"(^7\d{10}$)", str(value)):
            raise ValueError("Phone number must be 11 numbers long and start with the number 7")


class DateField(Field):
    def validate(self, value) -> None:
        if not value:
            return

        try:
            datetime.datetime.strptime(value, "%d.%m.%Y").astimezone(datetime.timezone.utc)
        except ValueError:
            raise ValueError("Date format must be DD.MM.YYYY") from None


class BirthDayField(Field):
    def validate(self, value) -> None:
        if not value:
            return

        try:
            date = datetime.datetime.strptime(value, "%d.%m.%Y").astimezone(datetime.timezone.utc)
        except ValueError:
            raise ValueError("Date format must be DD.MM.YYYY") from None

        if not (0 <= datetime.datetime.now(tz=datetime.timezone.utc).year - date.year <= 70):
            raise ValueError("Age must not exceed 70 years")


class GenderField(Field):
    def validate(self, value) -> None:
        if not value:
            return

        if not isinstance(value, int) or value not in [0, 1, 2]:
            raise ValueError("Must be either 0 or 1 or 2")


class ClientIDsField(Field):
    def validate(self, value) -> None:
        if not isinstance(value, list) or not value or not all(isinstance(item, int) for item in value):
            raise ValueError("Must be a list of client IDs")


class MethodRequest:
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)
    arguments = ArgumentsField(required=True, nullable=True)

    def __init__(self, account=None, login=None, token=None, method=None, arguments=None):
        self.account = account
        self.token = token
        self.login = login
        self.method = method
        self.arguments = arguments

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class ClientsInterestsRequest:
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, client_ids: list = None, date: datetime = None) -> None:
        self.client_ids = client_ids
        self.date = date

    def get_response(self, **kwargs) -> tuple[dict, int]:
        kwargs["context"]["nclients"] = len(self.client_ids)
        return {str(k): get_interests(store=kwargs["store"], cid=k) for k in self.client_ids}, OK


class OnlineScoreRequest:
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(
        self,
        first_name=None,
        last_name=None,
        email=None,
        phone=None,
        birthday=None,
        gender=None,
    ):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender

    def get_response(self, **kwargs) -> tuple[dict | int, int]:
        kwargs["context"]["has"] = [
            attr
            for attr in ["first_name", "last_name", "email", "phone", "birthday", "gender"]
            if getattr(self, attr) is not None
        ]

        if kwargs["request"].is_admin:
            return {"score": 42}, OK

        if not any(
            [
                all((self.phone is not None, self.email is not None)),
                all((self.first_name is not None, self.last_name is not None)),
                all((self.birthday is not None, self.gender is not None)),
            ]
        ):
            raise ValueError(
                f"Invalid request {self.__class__.__name__} must be at least one pair"
                "(phone-email) or (first name-last name) or (gender-birthday)"
            )

        score = get_score(
            store=kwargs["store"],
            phone=self.phone,
            email=self.email,
            birthday=self.birthday,
            gender=self.gender,
            first_name=self.first_name,
            last_name=self.last_name,
        )
        return {"score": score}, OK


def check_auth(request: MethodRequest) -> bool:
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%d%H") + ADMIN_SALT).encode(encoding="UTF-8")
        ).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode("UTF-8")).hexdigest()

    if digest == request.token:
        return True

    return False


def method_handler(request, ctx, store) -> tuple[dict, int]:
    body = request.get("body")

    if not body:
        return {"error": "Not body"}, INVALID_REQUEST

    methods = {
        "online_score": OnlineScoreRequest,
        "clients_interests": ClientsInterestsRequest,
    }

    try:
        mr = MethodRequest(
            account=body.get("account"),
            login=body.get("login"),
            token=body.get("token"),
            method=body.get("method"),
            arguments=body.get("arguments"),
        )
    except (ValueError, TypeError) as error:
        return {"error": str(error)}, INVALID_REQUEST

    if not check_auth(request=mr):
        return {"error": "Forbidden"}, FORBIDDEN

    if mr.method not in methods:
        return {"error": f"Unsupported method: {mr.method}"}, INVALID_REQUEST

    try:
        response, code = methods[mr.method](**mr.arguments).get_response(request=mr, context=ctx, store=store)
    except ValueError as error:
        return {"error": str(error)}, INVALID_REQUEST

    return response, code


class Store:
    data = {}

    def get(self, key):
        return self.data.get(key)

    def cache_get(self, key):
        return self.data.get(key)

    def cache_set(self, key, value, save_time):  # noqa: ARG002
        self.data.setdefault(key, value)


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "online_score": method_handler,
        "clients_interests": method_handler,
    }
    store = Store()  # TODO: replace on Redis

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):  # noqa: N802
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except Exception:
            logging.exception("Unexpected error")
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info(f"{self.path}: {data_string} {context['request_id']}")
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception:
                    logging.exception("Unexpected error")
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
        self.wfile.write(json.dumps(r).encode("UTF-8"))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    opts, args = op.parse_args()
    logging.basicConfig(
        filename=opts.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down")
    finally:
        server.server_close()
