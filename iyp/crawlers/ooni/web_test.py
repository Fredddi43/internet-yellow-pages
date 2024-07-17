import argparse
import logging
import os
import sys

# import tempfile
import json
import tldextract
import ipaddress
from collections import defaultdict

# from utils import grabber

from iyp import BaseCrawler

ORG = "OONI"
URL = "https://ooni.org/post/mining-ooni-data"
NAME = "ooni.web_test"


class Crawler(BaseCrawler):

    def __init__(self, organization, url, name):
        super().__init__(organization, url, name)
        self.repo = "ooni-data-eu-fra"

    def run(self):
        """Fetch data and push to IYP."""
        self.all_asns = set()
        self.all_ips = set()
        self.all_resolvers = set()
        self.all_results = list()
        self.all_percentages = defaultdict(lambda: defaultdict(dict))

        # Create a temporary directory
        # tmpdir = tempfile.mkdtemp()

        # Fetch data
        # grabber.download_and_extract(self.repo, tmpdir, "facebookmessenger")
        logging.info("Successfully downloaded and extracted all files")
        # Now that we have downloaded the jsonl files for the test we want, we can extract the data we want
        testdir = os.path.join(
            r"C:\Users\fried\Documents\internet-yellow-pages\ooni_jsonl",
            "tor",
        )
        for file_name in os.listdir(testdir):
            file_path = os.path.join(testdir, file_name)
            if os.path.isfile(file_path) and file_path.endswith(".jsonl"):
                with open(file_path, "r") as file:
                    for i, line in enumerate(file):
                        data = json.loads(line)
                        self.process_one_line(data)
                        logging.info(f"\rProcessed {i+1} lines")
        logging.info("\nProcessed lines, now calculating percentages\n")
        self.calculate_percentages()
        logging.info("\nCalculated percentages, now adding entries to IYP\n")
        self.batch_add_to_iyp()
        logging.info("\nSuccessfully added all entries to IYP\n")

    def process_one_line(self, one_line):
        """Process a single line from the jsonl file and store the results locally."""

        ips = {"ipv4": [], "ipv6": []}

        asn = (
            int(one_line.get("probe_asn")[2:])
            if one_line.get("probe_asn") and one_line.get("probe_asn").startswith("AS")
            else None
        )

        # Add the resolver to the set, unless it's not a valid IP address
        try:
            self.all_resolvers.add(
                ipaddress.ip_address(one_line.get("resolver_ip")).compressed
            )
        except ValueError:
            pass

        # Extract the IPs and categorize them
        for ip in one_line.get("ip_addresses", []):
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.version == 4:
                ips["ipv4"].append(ip)
            elif ip_addr.version == 6:
                ips["ipv6"].append(ip)

        tor_tags = {
            "tor_or_port_dirauth": {
                "percentage": one_line.get("tor_or_port_dirauth_percentage", 0),
                "count": one_line.get("tor_or_port_dirauth_count", 0),
            },
            "tor_dir_port": {
                "percentage": one_line.get("tor_dir_port_percentage", 0),
                "count": one_line.get("tor_dir_port_count", 0),
            },
            "tor_obfs4": {
                "percentage": one_line.get("tor_obfs4_percentage", 0),
                "count": one_line.get("tor_obfs4_count", 0),
            },
        }

        if asn and ips:
            self.all_asns.add(asn)
            for ip_type in ips.values():
                for ip in ip_type:
                    self.all_ips.add(ip)
                    self.all_results.append((asn, ip, tor_tags))

    def batch_add_to_iyp(self):
        """Batch add the collected data to IYP."""

        # First, add the nodes and store their IDs directly as returned dictionaries
        self.node_ids = {
            "asn": self.iyp.batch_get_nodes_by_single_prop("ASN", "asn", self.all_asns),
            "ip": self.iyp.batch_get_nodes_by_single_prop("IP", "ip", self.all_ips),
            "resolver": self.iyp.batch_get_nodes_by_single_prop(
                "IP", "ip", self.all_resolvers
            ),
        }

        censored_links = []

        # Process results and create links
        for asn, ip, tags in self.all_results:
            asn_id = self.node_ids["asn"].get(asn)
            ip_id = self.node_ids["ip"].get(ip)

            if asn_id and ip_id:
                props = {
                    "tor_or_port_dirauth_percentage": tags["tor_or_port_dirauth"][
                        "percentage"
                    ],
                    "tor_or_port_dirauth_count": tags["tor_or_port_dirauth"]["count"],
                    "tor_dir_port_percentage": tags["tor_dir_port"]["percentage"],
                    "tor_dir_port_count": tags["tor_dir_port"]["count"],
                    "tor_obfs4_percentage": tags["tor_obfs4"]["percentage"],
                    "tor_obfs4_count": tags["tor_obfs4"]["count"],
                }
                censored_links.append(
                    {"src_id": asn_id, "dst_id": ip_id, "props": props}
                )

        # Batch add the links (this is faster than adding them one by one)
        self.iyp.batch_add_links("CENSORED", censored_links)

        # Batch add node labels
        self.iyp.batch_add_node_label(
            list(self.node_ids["resolver"].values()), "Resolver"
        )

    def calculate_percentages(self):
        target_dict = defaultdict(lambda: defaultdict(int))

        # Populate the target_dict with counts
        for entry in self.all_results:
            asn, ip, tags = entry
            for category, values in tags.items():
                target_dict[(asn, ip)][category] += values["count"]

        self.all_percentages = {}

        for (asn, ip), counts in target_dict.items():
            total_count = sum(counts.values())
            percentages = {
                category: (count / total_count) * 100 if total_count > 0 else 0
                for category, count in counts.items()
            }
            result_dict = {
                "total_count": total_count,
                "category_counts": dict(counts),
                "percentages": percentages,
            }
            self.all_percentages[(asn, ip)] = result_dict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unit-test", action="store_true")
    args = parser.parse_args()

    scriptname = os.path.basename(sys.argv[0]).replace("/", "_")[0:-3]
    FORMAT = "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(
        format=FORMAT,
        filename="log/" + scriptname + ".log",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logging.info(f"Started: {sys.argv}")

    crawler = Crawler(ORG, URL, NAME)
    if args.unit_test:
        crawler.unit_test(logging)
    else:
        crawler.run()
        crawler.close()
    logging.info(f"Finished: {sys.argv}")


if __name__ == "__main__":
    main()
    sys.exit(0)
