import argparse
import google.auth
import re
import sys
import warnings
import time
import logging as log

from google.cloud import logging
from datetime import datetime, timedelta

# Disable this based on user flag
warnings.filterwarnings("ignore")

log_splitter = ":"
payload = "textPayload"
logging_df = "%Y-%m-%dT%H:%M:%S.%fZ"
log_part_pattern = r"^(\((?P<part>\d+)/(?P<parts>\d+)\)\s)"
log_identity_pattern = log_part_pattern + r"?\[\d+\]:\s\[\d+-\d+]\sdb=({database}),user=({users})"
req_init_pattern = log_identity_pattern + r"\s(LOG|DETAIL)"
log_init_pattern = log_identity_pattern.format(database=r"\S+", users=r"\S+")


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


def reset_verbose_mode(args):
    log_format = "%(levelname)s: %(message)s"
    if args["verbose"]:
        log.basicConfig(format=log_format, level=log.DEBUG)
    else:
        log.basicConfig(format=log_format)


def print_formatted_current(current_log, next_log, sink):
    if current_log is None or next_log is None:
        return

    if current_log["group"].endswith("LOG"):
        if next_log["group"].endswith("DETAIL") and next_log["action"] == "parameters":

            parsed_args = {}
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

        current_log["sql"] = current_log["sql"] + ";" if current_log["sql"][-1] != ";" else current_log["sql"]
        print(current_log["sql"], file=sink)


def generate_query_filter(args):
    filters = 'resource.type="cloudsql_database" AND ' \
              'timestamp >= "{start_time}" AND ' \
              'timestamp <= "{end_time}" AND ' \
              'resource.labels.database_id="{project}:{instance}"'

    filters += ' AND ({custom_filters})' if args["custom_filters"] is not None else ''
    return filters.format(**args)


def merge_payloads(first_payload, next_payload, merge_index):
    first_match = re.match(log_part_pattern, first_payload)
    next_match = re.match(log_part_pattern, next_payload)

    if first_match is None and next_match is None:
        first_payload += next_payload

    elif first_match is not None and next_match is not None and \
            int(first_match.group("part")) == 1 and int(next_match.group("part")) == (merge_index + 1):
        first_payload += re.split(log_part_pattern, next_payload, maxsplit=1)[-1]

    else:
        raise Exception("Merger out of sync !")

    return first_payload


def get_data_node(req_log):
    splits = req_log[payload].split(log_splitter) if req_log is not None else None
    if splits is not None and len(splits) >= 4:
        return {
            "pid": splits[0].strip(),
            "group": splits[1].strip(),
            "action": splits[2].strip(),
            "sql": log_splitter.join(splits[3:]).strip()
        }

    else:
        return None


def generate_logs(args):
    credentials, project = google.auth.default()
    logging_client = logging.Client(credentials=credentials)
    filters = generate_query_filter(args)
    log.debug("gCloud Query Filters : '%s'", filters)

    with args["output"] as out:
        args["users"] = r"\S+" if args["users"] is None else r"|".join([u for u in set(args["users"])])
        query_init_pattern = req_init_pattern.format(**args)
        log.debug("Log Init Pattern : %s", log_init_pattern)
        log.debug("Query Init Pattern : %s", query_init_pattern)

        prev_req_log, curr_req_log, curr_entry = None, None, None
        iterator = logging_client.list_entries(projects=[args["project"]], filter_=filters, page_size=args["page_size"])
        pages = iterator.pages

        is_req_init = False
        merge_index = 1

        while True:
            try:
                page = next(pages)
            except StopIteration as e:
                break

            for entry in page:
                log.debug("Received : %s", entry)
                curr_entry = entry.to_api_repr()

                is_init = (re.match(log_init_pattern, curr_entry[payload]) is not None)

                if is_init:
                    merge_index = 1
                    is_req_init = (re.match(query_init_pattern, curr_entry[payload]) is not None)
                    if is_req_init:
                        print_formatted_current(get_data_node(prev_req_log), get_data_node(curr_req_log), out)
                        prev_req_log = curr_req_log
                        curr_req_log = curr_entry

                else:
                    if is_req_init:
                        curr_req_log[payload] = merge_payloads(curr_req_log[payload], curr_entry[payload], merge_index)
                        merge_index += 1

            time.sleep(args["delay"])

        print_formatted_current(get_data_node(prev_req_log), get_data_node(curr_req_log), out)
        print_formatted_current(get_data_node(curr_req_log), get_data_node(curr_req_log), out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A disaster recovery command line utility to fetch Google Cloud SQL (Postgres) transaction logs."
                    "Default date range is set to last 7 days.",
        conflict_handler="resolve",
        epilog="Report bugs at patil.sm17@gmail.com")

    mandatory_group = parser.add_argument_group("mandatory arguments", "Args that must be supplied")
    mandatory_group.add_argument("-P", "--project", dest="project", help="GCP project id", required=True)
    mandatory_group.add_argument("-i", "--instance", dest="instance", help="GCP Cloud SQL instance name",
                                 required=True)
    mandatory_group.add_argument("-d", "--database", dest="database", help="GCP Cloud SQL postgres database name")

    parser.add_argument("-u", "--user", dest="users", action="append", help="GCP Cloud SQL Postgres User")
    parser.add_argument("-st", "--start-time", dest="start_time",
                        action=DatetimeParseAction,
                        default=(datetime.now() - timedelta(days=7)).strftime(logging_df),
                        help="Start time in standard UTC format. Defaults to 7 days ago.")
    parser.add_argument("-et", "--end-time", dest="end_time",
                        action=DatetimeParseAction, default=datetime.now().strftime(logging_df),
                        help="End time in standard UTC format. Defaults to now.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType('w'), default=sys.stdout,
                        help="Output file to write in.")
    parser.add_argument("-c", "--custom-filters", dest="custom_filters", help="Custom filters to add to the query")
    parser.add_argument("-p", "--page-size", dest="page_size", type=int, default=100,
                        help="Page size to fetch in a single API call (number of records)")
    parser.add_argument("-w", "--wait", dest="delay", type=int, default=2,
                        help="Delay between API calls (in seconds)")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode (shows debug logs)")

    args = vars(parser.parse_args())
    reset_verbose_mode(args)
    generate_logs(args)
