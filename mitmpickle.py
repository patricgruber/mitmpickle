import pickle
from mitmproxy import ctx


def to_dict(request, response):
    req_data = request.data
    res_data = response.data

    request_headers = {}
    for key, value in req_data.headers.fields:
        request_headers[key.decode().lower()] = value.decode()

    response_headers = {"set-cookie": []}
    for key, value in res_data.headers.fields:
        if key.decode().lower() == "set-cookie":
            response_headers["set-cookie"] += [value.decode()]
        else:
            response_headers[key.decode().lower()] = value.decode()

    return {
        "request": {
            "method": req_data.method,
            "url": request.url,
            "http_version": req_data.http_version,
            "headers": request_headers,
            "content": req_data.content
        },
        "response": {
            "status_code": res_data.status_code,
            "reason": res_data.reason,
            "http_version": res_data.http_version,
            "headers": response_headers,
            "content": res_data.content
        }
    }


class HTTPSave:
    def __init__(self, filename="capture.pkl"):
        self.filename = filename
        with open(self.filename, "wb") as output_file:
            pickle.dump([], output_file)

    def response(self, flow):
        self.save(flow)

    def save(self, flow):
        http_pair_dict = to_dict(flow.request, flow.response)
        with open(self.filename, "rb") as output_file:
            file_list = pickle.load(output_file)
        file_list.append(http_pair_dict)
        with open(self.filename, "wb") as output_file:
            pickle.dump(file_list, output_file)


addons = [
    HTTPSave()
]
