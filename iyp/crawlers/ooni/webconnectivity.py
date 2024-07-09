import argparse
import logging
import os
import sys
import tempfile
import json
from collections import defaultdict

from utils import grabber

from iyp import BaseCrawler, RequestStatusError

ORG = "OONI"
URL = "https://ooni.org/post/mining-ooni-data"
NAME = "ooni.webconnectivity"


class Crawler(BaseCrawler):

    def __init__(self, organization, url, name):
        super().__init__(organization, url, name)
        self.repo = "ooni-data-eu-fra"

    def run(self):
        """Fetch data and push to IYP."""

        self.all_asns = set()
        self.all_domains = set()
        self.all_countries = set()
        self.all_results = list()
        self.all_percentages = list()

        # Create a temporary directory
        tmpdir = tempfile.mkdtemp()

        # Fetch data
        grabber.download_and_extract(self.repo, tmpdir, "webconnectivity")
        logging.info("Successfully downloaded and extracted all files")
        # Now that we have downloaded the jsonl files for the test we want, we can extract the data we want
        testdir = os.path.join(tmpdir, "webconnectivity")
        for file_name in os.listdir(testdir):
            file_path = os.path.join(
                testdir,
                file_name,
            )
            if os.path.isfile(file_path) and file_path.endswith(".jsonl"):
                with open(file_path, "r") as file:
                    for i, line in enumerate(file):
                        data = json.loads(line)
                        self.process_one_line(data)
                        logging.info(f"\rProcessed {i+1} lines")
        logging.info("\n Processed lines, now calculating percentages\n")
        self.calculate_percentages()
        logging.info("\n Calculated percentages, now adding entries to IYP\n")
        self.batch_add_to_iyp()
        logging.info("\n Successfully added all entries to IYP\n")

    # process a single line from the jsonl file and store the results locally
    def process_one_line(self, one_line):
        """Add the entry to IYP if it's not already there and update its properties."""

        probe_asn = (
            int(one_line.get("probe_asn")[2:])
            if one_line.get("probe_asn") and one_line.get("probe_asn").startswith("AS")
            else None
        )
        probe_cc = one_line.get("probe_cc")
        input_domain = one_line.get("input")
        test_keys = one_line.get("test_keys", {})
        blocking = test_keys.get("blocking")
        accessible = test_keys.get("accessible")

        # Ensure all required fields are present
        if probe_asn and probe_cc and input_domain and test_keys:
            # Determine the result based on the table (https://github.com/ooni/spec/blob/master/nettests/ts-017-web-connectivity.md)
            if blocking is None and accessible is None:
                result = "Failure"  # Could not assign values to the fields
            elif blocking is False and accessible is False:
                result = "Failure"  # Expected failures (e.g., the website down)
            elif blocking is False and accessible is True:
                result = "OK"  # Expected success (i.e., no censorship)
            elif blocking == "dns" and accessible is False:
                result = "Confirmed"  # DNS-based blocking
            elif blocking == "tcp_ip" and accessible is False:
                result = "Confirmed"  # TCP-based blocking
            elif blocking == "http-failure" and accessible is False:
                result = "Confirmed"  # HTTP or TLS based blocking
            elif blocking == "http-diff" and accessible is False:
                result = "Confirmed"  # Blockpage rather than legit page
            else:
                result = "Anomaly"  # Default case if no other case matches

        # Append the results to the list
        self.all_asns.add(probe_asn)
        self.all_countries.add(probe_cc)
        self.all_domains.add(input_domain)
        self.all_results.append((probe_asn, probe_cc, input_domain, result))

    # now we add all the entries to IYP
    def batch_add_to_iyp(self):
        # First, add the nodes and store their IDs
        asn_ids = self.iyp.batch_get_nodes_by_single_prop(
            "AS", "asn", self.all_asns, all=False
        )
        country_ids = self.iyp.batch_get_nodes_by_single_prop(
            "Country", "country_code", self.all_countries, all=False
        )
        domain_ids = self.iyp.batch_get_nodes_by_single_prop(
            "URL", "url", self.all_domains, all=False
        )

        # Store the IDs in a structured format for easy mapping
        self.node_ids = {
            "asn": asn_ids,
            "country": country_ids,
            "domain": domain_ids,
        }

        country_links = []
        censored_links = []

        # Ensure all IDs are present
        for (asn, country, domain), results in self.all_percentages.items():
            # Retrieve the IDs for the current asn, domain, and country
            asn_id = self.node_ids["asn"].get(asn)
            domain_id = self.node_ids["domain"].get(domain)
            country_id = self.node_ids["country"].get(country)

            # Ensure both IDs are present
            if asn_id and domain_id:
                percentages = results.get("percentages", {})
                # Create link properties
                props = [{"property": "reference_org", "value": "OONI"}]
                # Add percentages to the props
                for category, percentage in percentages.items():
                    props.append(
                        {"property": f"percentage_{category}", "value": percentage}
                    )

                # Add link to the list
                censored_links.append(
                    {"src_id": asn_id, "dst_id": domain_id, "props": props}
                )

            # Ensure both IDs are present
            if asn_id and country_id:
                props = [{"property": "reference_org", "value": "OONI"}]

                # Add link to the list
                country_links.append(
                    {"src_id": asn_id, "dst_id": country_id, "props": props}
                )

        self.iyp.batch_add_links("CENSORED", censored_links)
        self.iyp.batch_add_links("COUNTRY", country_links)

    # calculate the percentages of the results
    def calculate_percentages(self):
        target_dict = defaultdict(lambda: defaultdict(int))

        # Populate the target_dict with counts
        for entry in self.all_results:
            asn, country, target, result = entry
            target_dict[(asn, country, target)][result] += 1

        self.all_percentages = {}

        for (asn, country, target), counts in target_dict.items():
            total_count = sum(counts.values())
            percentages = {
                category: (count / total_count) * 100
                for category, count in counts.items()
            }
            result_dict = {
                "total_count": total_count,
                "category_counts": dict(counts),
                "percentages": percentages,
            }
            self.all_percentages[(asn, country, target)] = result_dict


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
