import argparse
import google.auth
import re
import sys
import warnings
import time

from google.cloud import logging
from datetime import datetime, timedelta

# Disable this based on user flag
warnings.filterwarnings("ignore")

log_splitter = ":"
logging_df = "%Y-%m-%dT%H:%M:%S.%fZ"

blacklist_sql = [
    "Connection reset by peer"
]


class DatetimeParseAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")

        super(DatetimeParseAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            ts = datetime.strptime(values, logging_df)
            setattr(namespace, self.dest, ts.strftime(logging_df))
        except Exception as e:
            raise argparse.ArgumentError(self, e)


def print_log(data, sink):
    if data["group"].endswith("LOG") and data["sql"] not in blacklist_sql:
        data["sql"] = data["sql"] + ";" if data["sql"][-1] != ";" else data["sql"]
        print(data["sql"], file=sink)


def print_formatted_current(current_log, next_log, sink):
    parsed_args = {}

    if next_log["action"] == "parameters":
        temp_sql = next_log["sql"]
        key_args = [int(x.strip('$')) for x in re.findall("\$\d+", current_log["sql"])]
        for idx, key in enumerate(key_args):
            current_arg = "${pos} = ".format(pos=key)
            next_arg = "${pos} = ".format(pos=(key + 1))
            start = "^(?P<start>\\{current_arg})".format(current_arg=current_arg)
            end = ("$" if idx == len(key_args) - 1 else "(?P<end>, \\{next_arg})".format(next_arg=next_arg))
            pattern = "{start}(?P<value>.*){end}".format(start=start, end=end)
            match = re.match(pattern, temp_sql)
            if match:
                temp_sql = next_arg + re.split(pattern, temp_sql, 1)[-1]
                parsed_args["$" + str(key)] = match.group("value")

        for key in sorted(key_args, reverse=True):
            arg = "$" + str(key)
            current_log["sql"] = current_log["sql"].replace(arg, parsed_args[arg])

    print_log(current_log, sink)


def generate_query_filter(args):
    filters = 'resource.type="cloudsql_database" AND ' \
              'timestamp >= "{start_time}" AND ' \
              'timestamp <= "{end_time}" AND ' \
              '("LOG:" OR "DETAIL:")'

    filters += ' AND resource.labels.database_id="{project}:{host}"' if args["host"] is not None else ''
    filters += ' AND ({})'.format(" OR ".join(['"db={database},user={user}"'
                                              .format(database=args["database"], user=user)
                                               for user in set(args["user"])]))
    filters += ' AND ({custom_filters})' if args["custom_filters"] is not None else ''
    return filters.format(**args)


def generate_logs(args):
    credentials, project = google.auth.default()
    logging_client = logging.Client(credentials=credentials)

    with args["output"] as out:
        current_log, next_log = None, None
        filters = generate_query_filter(args)
        iterator = logging_client.list_entries(projects=[args["project"]], filter_=filters, page_size=args["page_size"])
        pages = iterator.pages

        while True:
            try:
                page = next(pages)
            except StopIteration as e:
                break

            for entry in page:
                payload = entry.to_api_repr()['textPayload']
                splits = payload.split(log_splitter)

                data = {
                    "pid": splits[0].strip(),
                    "group": splits[1].strip(),
                    "action": splits[2].strip(),
                    "sql": log_splitter.join(splits[3:]).strip()
                }

                if next_log is None:
                    if current_log is None:
                        current_log = data
                    else:
                        next_log = data
                        print_formatted_current(current_log, next_log, out)

                else:
                    current_log = next_log
                    next_log = data
                    print_formatted_current(current_log, next_log, out)

            time.sleep(args["delay"])

        if current_log is not None and next_log is None:
            print_log(current_log, out)
        elif next_log is not None:
            print_log(next_log, out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A disaster recovery command line utility to fetch Google Cloud SQL (Postgres) transaction logs."
                    "Default date range is set to last 7 days.",
        conflict_handler="resolve",
        epilog="Report bugs at patil.sm17@gmail.com")

    mandatory_group = parser.add_argument_group("mandatory arguments", "Args that must be supplied")
    mandatory_group.add_argument("-p", "--project", dest="project", help="Google Cloud Project Id", required=True)

    parser.add_argument("-h", "--host", dest="host", help="Google Cloud SQL Hostname")
    parser.add_argument("-d", "--database", dest="database", help="Google Cloud SQL postgres instance name")
    parser.add_argument("-u", "--user", dest="user", action="append", help="Google Cloud SQL Postgres User")
    parser.add_argument("-st", "--start-time", dest="start_time",
                        action=DatetimeParseAction,
                        default=(datetime.now() - timedelta(days=7)).strftime(logging_df),
                        help="Start time in standard ISO format. Defaults to 7 days ago.")
    parser.add_argument("-et", "--end-time", dest="end_time",
                        action=DatetimeParseAction, default=datetime.now().strftime(logging_df),
                        help="End time in standard ISO format. Defaults to now.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType('w'), default=sys.stdout,
                        help="Output file to write in.")
    parser.add_argument("-c", "--custom-filter", dest="custom_filters", help="Custom filters to add to the query")
    parser.add_argument("-p", "--page-size", dest="page_size", type=int, default=10,
                        help="Page size to fetch in a single API call (number of records)")
    parser.add_argument("-w", "--wait", dest="delay", type=int, default=1,
                        help="Delay between API calls (in seconds)")
    parser.add_argument("-v", "--verbose", dest="verbose_mode", action="store_true")

    args = parser.parse_args()
    generate_logs(vars(args))
