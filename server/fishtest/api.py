import base64
import copy
import io
import re
from datetime import datetime, timezone

from fishtest.schemas import api_access_schema, api_schema, gzip_data
from fishtest.stats.stat_util import SPRT_elo, get_elo
from fishtest.util import worker_name
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPFound,
    HTTPUnauthorized,
    exception_response,
)
from pyramid.response import FileIter, Response
from pyramid.view import exception_view_config, view_config, view_defaults
from vtjson import ValidationError, validate

"""
Important note
==============

All APIs that rely on the `run_cache` of `rundb.get_run()`
must be served from the main Fishtest instance.
Note that `self.validate_request("/api/<route>")`
uses `rundb.get_run()` under some conditions.

If other Fishtest instances need information about runs,
they should query the database directly.
However, keep in mind that this information might be slightly outdated.
This depends on how frequently the main instance flushes its `run_cache`.
"""

WORKER_VERSION = 236


def validate_request(request):
    validate(api_schema, request, "request")


# Avoids exposing sensitive data about the workers to the client and skips some heavy data.
def strip_run(run):
    # a deep copy, avoiding copies of a few large lists.
    stripped = {}
    for k1, v1 in run.items():
        if k1 in ("tasks", "bad_tasks"):
            stripped[k1] = []
        elif k1 == "args":
            stripped[k1] = {}
            for k2, v2 in v1.items():
                if k2 == "spsa":
                    stripped[k1][k2] = {
                        k3: [] if k3 == "param_history" else copy.deepcopy(v3)
                        for k3, v3 in v2.items()
                    }
                else:
                    stripped[k1][k2] = copy.deepcopy(v2)
        else:
            stripped[k1] = copy.deepcopy(v1)

    # and some string conversions
    for key in ("_id", "start_time", "last_updated"):
        stripped[key] = str(run[key])

    return stripped


@exception_view_config(HTTPBadRequest)
def badrequest_failed(error, request):
    response = Response(json_body=error.detail)
    response.status_int = 400
    return response


@exception_view_config(HTTPUnauthorized)
def authentication_failed(error, request):
    response = Response(json_body=error.detail)
    response.status_int = 401
    return response


@view_defaults(renderer="json")
class ApiView(object):
    """All API endpoints that require authentication are used by workers"""

    def __init__(self, request):
        self.request = request

    def handle_error(self, error, exception=HTTPBadRequest):
        if error != "":
            error = "{}: {}".format(self.__api, error)
            print(error, flush=True)
            raise exception(self.add_time({"error": error}))

    def validate_username_password(self, api):
        self.__t0 = datetime.now(timezone.utc)
        self.__api = api
        # is the request valid json?
        try:
            self.request_body = self.request.json_body
        except:
            self.handle_error("request is not json encoded")

        # Is the request syntactically correct?
        try:
            validate(api_access_schema, self.request_body, "request")
        except ValidationError as e:
            self.handle_error(str(e))

        # is the supplied password correct?
        token = self.request.userdb.authenticate(
            self.request_body["worker_info"]["username"],
            self.request_body["password"],
        )
        if "error" in token:
            self.handle_error(
                token["error"],
                exception=HTTPUnauthorized,
            )

    def validate_request(self, api):
        self.__run = None
        self.__task = None

        # Preliminary validation.
        self.validate_username_password(api)

        # Is the request syntactically correct?
        try:
            validate_request(self.request_body)
        except ValidationError as e:
            self.handle_error(str(e))

        # is a supplied run_id correct?
        if "run_id" in self.request_body:
            run_id = self.request_body["run_id"]
            run = self.request.rundb.get_run(run_id)
            if run is None:
                self.handle_error("Invalid run_id: {}".format(run_id))
            self.__run = run

        # if a task_id is present then the unique_key should correspond
        # to the unique_key of the task

        if "task_id" in self.request_body:
            task_id = self.request_body["task_id"]

            if task_id < 0 or task_id >= len(run["tasks"]):
                self.handle_error(
                    "Invalid task_id {} for run_id {}".format(task_id, run_id)
                )

            task = run["tasks"][task_id]
            unique_key = self.request_body["worker_info"]["unique_key"]
            if unique_key != task["worker_info"]["unique_key"]:
                self.handle_error(
                    "Invalid unique key {} for task_id {} for run_id {}".format(
                        unique_key, task_id, run_id
                    )
                )
            self.__task = task

    def add_time(self, result):
        result["duration"] = (datetime.now(timezone.utc) - self.__t0).total_seconds()
        return result

    def get_username(self):
        return self.request_body["worker_info"]["username"]

    def run(self):
        if self.__run is not None:
            return self.__run

        self.handle_error("Missing run_id")

    def run_id(self):
        if "run_id" in self.request_body:
            return self.request_body["run_id"]

        self.handle_error("Missing run_id")

    def task(self):
        if self.__task is not None:
            return self.__task

        self.handle_error("Missing task_id")

    def task_id(self):
        if "task_id" in self.request_body:
            return self.request_body["task_id"]

        self.handle_error("Missing task_id")

    def pgn(self):
        if "pgn" in self.request_body:
            return self.request_body["pgn"]

        self.handle_error("Missing pgn content")

    def worker_info(self):
        worker_info = self.request_body["worker_info"]
        worker_info["remote_addr"] = self.request.remote_addr
        worker_info["country_code"] = self.get_country_code()
        return worker_info

    def worker_name(self):
        return worker_name(self.worker_info())

    def cpu_hours(self):
        username = self.get_username()
        user = self.request.userdb.user_cache.find_one({"username": username})
        return -1 if user is None else user["cpu_hours"]

    def message(self):
        return self.request_body.get("message", "")

    def stats(self):
        return self.request_body.get("stats", {})

    def spsa(self):
        return self.request_body.get("spsa", {})

    def get_country_code(self):
        country_code = self.request.headers.get("X-Country-Code")
        return "?" if country_code in (None, "ZZ") else country_code

    @view_config(route_name="api_active_runs")
    def active_runs(self):
        runs = self.request.rundb.runs.find(
            {"finished": False},
            {"tasks": 0, "bad_tasks": 0, "args.spsa.param_history": 0},
        )
        active = {}
        for run in runs:
            # some string conversions
            for key in ("_id", "start_time", "last_updated"):
                run[key] = str(run[key])
            active[str(run["_id"])] = run
        return active

    @view_config(route_name="api_finished_runs")
    def finished_runs(self):
        self.__t0 = datetime.now(timezone.utc)
        self.__api = "/api/finished_runs"

        username = self.request.params.get("username", "")
        success_only = self.request.params.get("success_only", False)
        yellow_only = self.request.params.get("yellow_only", False)
        ltc_only = self.request.params.get("ltc_only", False)
        timestamp = self.request.params.get("timestamp", "")
        page_param = self.request.params.get("page", "")

        if page_param == "":
            self.handle_error("Please provide a Page number.")
        if not page_param.isdigit() or int(page_param) < 1:
            self.handle_error("Please provide a valid Page number.")
        page_idx = int(page_param) - 1
        page_size = 50

        last_updated = None
        if timestamp != "" and re.match(r"^\d{10}(\.\d+)?$", timestamp):
            last_updated = datetime.fromtimestamp(float(timestamp))
        elif timestamp != "":
            self.handle_error("Please provide a valid UNIX timestamp.")

        runs, num_finished = self.request.rundb.get_finished_runs(
            username=username,
            success_only=success_only,
            yellow_only=yellow_only,
            ltc_only=ltc_only,
            skip=page_idx * page_size,
            limit=page_size,
            last_updated=last_updated,
        )

        finished = {}
        for run in runs:
            # some string conversions
            for key in ("_id", "start_time", "last_updated"):
                run[key] = str(run[key])
            finished[str(run["_id"])] = run
        return finished

    @view_config(route_name="api_actions")
    def actions(self):
        try:
            query = self.request.json_body
            actions = self.request.rundb.db["actions"].find(query).limit(200)
        except:
            actions = []
        ret = []
        for action in actions:
            action["_id"] = str(action["_id"])
            ret.append(action)
        self.request.response.headers["access-control-allow-origin"] = "*"
        self.request.response.headers["access-control-allow-headers"] = "content-type"
        return ret

    @view_config(route_name="api_get_run")
    def get_run(self):
        run = self.request.rundb.get_run(self.request.matchdict["id"])
        if run is None:
            raise exception_response(404)
        return strip_run(run)

    @view_config(route_name="api_get_task")
    def get_task(self):
        try:
            run = self.request.rundb.get_run(self.request.matchdict["id"])
            task_id = self.request.matchdict["task_id"]
            if task_id.endswith("bad"):
                task_id = int(task_id[:-3])
                task = copy.deepcopy(run["bad_tasks"][task_id])
            else:
                task_id = int(task_id)
                task = copy.deepcopy(run["tasks"][task_id])
        except:
            raise exception_response(404)
        if "worker_info" in task:
            worker_info = task["worker_info"]
            # Do not reveal the unique_key.
            if "unique_key" in worker_info:
                unique_key = worker_info["unique_key"]
                worker_info["unique_key"] = unique_key[0:8] + "..."
            # Do not reveal remote_addr.
            if "remote_addr" in worker_info:
                worker_info["remote_addr"] = "?.?.?.?"
        if "last_updated" in task:
            # json does not know about datetime
            task["last_updated"] = str(task["last_updated"])
        if "residual" in task:
            # json does not know about infinity
            if task["residual"] == float("inf"):
                task["residual"] = "inf"
        return task

    @view_config(route_name="api_get_elo")
    def get_elo(self):
        run = self.request.rundb.get_run(self.request.matchdict["id"])
        if run is None:
            raise exception_response(404)
        results = run["results"]
        if "sprt" not in run["args"]:
            return {}
        run = strip_run(run)
        sprt = run["args"].get("sprt")
        elo_model = sprt.get("elo_model", "BayesElo")
        alpha = sprt["alpha"]
        beta = sprt["beta"]
        elo0 = sprt["elo0"]
        elo1 = sprt["elo1"]
        sprt["elo_model"] = elo_model
        a = SPRT_elo(
            results, alpha=alpha, beta=beta, elo0=elo0, elo1=elo1, elo_model=elo_model
        )
        run["elo"] = a
        return run

    @view_config(route_name="api_calc_elo")
    def calc_elo(self):
        self.__t0 = datetime.now(timezone.utc)
        self.__api = "/api/calc_elo"

        W = self.request.params.get("W")
        D = self.request.params.get("D")
        L = self.request.params.get("L")
        LL = self.request.params.get("LL")
        LD = self.request.params.get("LD")
        DDWL = self.request.params.get("DDWL")
        WD = self.request.params.get("WD")
        WW = self.request.params.get("WW")
        elo0 = self.request.params.get("elo0", "")
        elo1 = self.request.params.get("elo1", "")

        is_ptnml = all(
            value is not None and value.replace(".", "").replace("-", "").isdigit()
            for value in (LL, LD, DDWL, WD, WW)
        )

        is_ptnml = is_ptnml and all(int(value) >= 0 for value in (LL, LD, DDWL, WD, WW))

        is_wdl = not is_ptnml and all(
            value is not None and value.replace(".", "").replace("-", "").isdigit()
            for value in (W, D, L)
        )

        is_wdl = is_wdl and all(int(value) >= 0 for value in (W, D, L))

        if not is_ptnml and not is_wdl:
            self.handle_error(
                "Invalid or missing parameters. Please provide all values as valid numbers."
            )

        if is_ptnml:
            LL = int(LL)
            LD = int(LD)
            DDWL = int(DDWL)
            WD = int(WD)
            WW = int(WW)
            if (LL + LD + DDWL + WD + WW) * 2 > 2**32:
                self.handle_error("Number of games exceeds the limit.")
            if LL + LD + DDWL + WD + WW == 0:
                self.handle_error("No games to calculate Elo.")
            results = {
                "pentanomial": [LL, LD, DDWL, WD, WW],
            }
        if is_wdl:
            W = int(W)
            D = int(D)
            L = int(L)
            if W + D + L > 2**32:
                self.handle_error("Number of games exceeds the limit.")
            if W + D + L == 0:
                self.handle_error("No games to calculate Elo.")
            results = {
                "wins": W,
                "draws": D,
                "losses": L,
            }

        is_sprt = elo0 != "" and elo1 != ""

        if not is_sprt:  # fixed games
            if "pentanomial" in results:
                elo5, elo95_5, LOS5 = get_elo(results["pentanomial"])
                elo5_l = elo5 - elo95_5
                elo5_u = elo5 + elo95_5
                return {"elo": elo5, "ci": [elo5_l, elo5_u], "LOS": LOS5}
            else:
                WLD = [results["wins"], results["losses"], results["draws"]]
                elo3, elo95_3, LOS3 = get_elo([WLD[1], WLD[2], WLD[0]])
                elo3_l = elo3 - elo95_3
                elo3_u = elo3 + elo95_3
                return {"elo": elo3, "ci": [elo3_l, elo3_u], "LOS": LOS3}
        else:
            badEloValues = (
                not all(
                    value.replace(".", "").replace("-", "").isdigit()
                    for value in (elo0, elo1)
                )
                or float(elo1) < float(elo0) + 0.5
                or abs(float(elo0)) > 10
                or abs(float(elo1)) > 10
            )
            if badEloValues:
                self.handle_error("Bad elo0, and elo1 values.")

            elo_model = self.request.params.get("elo_model", "normalized")

            if elo_model not in ["BayesElo", "logistic", "normalized"]:
                self.handle_error(
                    "Valid Elo models are: BayesElo, logistic, and normalized."
                )

            elo0 = float(elo0)
            elo1 = float(elo1)
            alpha = 0.05
            beta = 0.05
            return SPRT_elo(
                results,
                alpha=alpha,
                beta=beta,
                elo0=elo0,
                elo1=elo1,
                elo_model=elo_model,
            )

    @view_config(route_name="api_request_task")
    def request_task(self):
        self.validate_request("/api/request_task")
        worker_info = self.worker_info()
        # rundb.request_task() needs this for an error message...
        worker_info["host_url"] = self.request.host_url
        result = self.request.rundb.request_task(worker_info)
        if "task_waiting" in result:
            return self.add_time(result)

        # Strip the run of unneccesary information
        run = result["run"]
        task = run["tasks"][result["task_id"]]
        min_task = {"num_games": task["num_games"], "start": task["start"]}
        if "stats" in task:
            min_task["stats"] = task["stats"]
        min_run = {"_id": str(run["_id"]), "args": run["args"], "my_task": min_task}
        result["run"] = min_run
        return self.add_time(result)

    @view_config(route_name="api_update_task")
    def update_task(self):
        self.validate_request("/api/update_task")
        result = self.request.rundb.update_task(
            worker_info=self.worker_info(),
            run_id=self.run_id(),
            task_id=self.task_id(),
            stats=self.stats(),
            spsa=self.spsa(),
        )
        return self.add_time(result)

    @view_config(route_name="api_failed_task")
    def failed_task(self):
        self.validate_request("/api/failed_task")
        result = self.request.rundb.failed_task(
            self.run_id(), self.task_id(), self.message()
        )
        return self.add_time(result)

    @view_config(route_name="api_upload_pgn")
    def upload_pgn(self):
        self.validate_request("/api/upload_pgn")
        try:
            pgn_zip = base64.b64decode(self.pgn())
            validate(gzip_data, pgn_zip, "pgn")
        except Exception as e:
            self.handle_error(str(e))
        result = self.request.rundb.upload_pgn(
            run_id="{}-{}".format(self.run_id(), self.task_id()),
            pgn_zip=pgn_zip,
        )
        return self.add_time(result)

    @view_config(route_name="api_download_pgn", renderer="string")
    def download_pgn(self):
        zip_name = self.request.matchdict["id"]
        run_id = zip_name.split(".")[0]  # strip .pgn
        pgn_zip, size = self.request.rundb.get_pgn(run_id)
        if pgn_zip is None:
            return Response("No data found", status=404)
        response = Response(content_type="application/gzip")
        response.app_iter = io.BytesIO(pgn_zip)
        response.headers["Content-Disposition"] = f'attachment; filename="{zip_name}"'
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Content-Length"] = str(size)
        return response

    @view_config(route_name="api_download_run_pgns")
    def download_run_pgns(self):
        pgns_name = self.request.matchdict["id"]
        match = re.match(r"^([a-zA-Z0-9]+)\.pgn\.gz$", pgns_name)
        if not match:
            return Response("Invalid filename format", status=400)
        run_id = match.group(1)
        pgns_reader, total_size = self.request.rundb.get_run_pgns(run_id)
        if pgns_reader is None:
            return Response("No data found", status=404)
        response = Response(content_type="application/gzip")
        response.app_iter = FileIter(pgns_reader)
        response.headers["Content-Disposition"] = f'attachment; filename="{pgns_name}"'
        response.headers["Content-Length"] = str(total_size)
        return response

    @view_config(route_name="api_download_nn")
    def download_nn(self):
        nn = self.request.rundb.get_nn(self.request.matchdict["id"])
        if nn is None:
            raise exception_response(404)
        else:
            self.request.rundb.increment_nn_downloads(self.request.matchdict["id"])

        return HTTPFound(
            "https://data.stockfishchess.org/nn/" + self.request.matchdict["id"]
        )

    @view_config(route_name="api_stop_run")
    def stop_run(self):
        api = "/api/stop_run"
        self.validate_request(api)
        error = ""
        if self.cpu_hours() < 1000:
            error = "User {} has too few games to stop a run".format(
                self.get_username()
            )
        with self.request.rundb.active_run_lock(self.run_id()):
            run = self.run()
            message = self.message()[:1024] + (
                " (not authorized)" if error != "" else ""
            )
            self.request.actiondb.stop_run(
                username=self.get_username(),
                run=run,
                task_id=self.task_id(),
                message=message,
            )
            if error == "":
                run["finished"] = True
                run["failed"] = True
                self.request.rundb.stop_run(self.run_id())
            else:
                task = self.task()
                task["active"] = False
                self.request.rundb.buffer(run, True)

        self.handle_error(error, exception=HTTPUnauthorized)
        return self.add_time({})

    @view_config(route_name="api_request_version")
    def request_version(self):
        # By being mor lax here we can be more strict
        # elsewhere since the worker will upgrade.
        self.validate_username_password("/api/request_version")
        return self.add_time({"version": WORKER_VERSION})

    @view_config(route_name="api_beat")
    def beat(self):
        self.validate_request("/api/beat")
        run = self.run()
        task = self.task()
        task["last_updated"] = datetime.now(timezone.utc)
        self.request.rundb.buffer(run, False)
        return self.add_time({})

    @view_config(route_name="api_request_spsa")
    def request_spsa(self):
        self.validate_request("/api/request_spsa")
        result = self.request.rundb.request_spsa(self.run_id(), self.task_id())
        return self.add_time(result)
