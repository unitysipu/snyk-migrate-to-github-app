"""
Primary logic for the CLI Tool
"""

# ===== IMPORTS =====

import json

import requests
import typer
from rich import print
from typing_extensions import Annotated

# import http.client as http_client  # NOSONAR

# http_client.HTTPConnection.debuglevel = 1  # NOSONAR


# ===== CONSTANTS =====

VALID_TENANTS = ["", "au", "eu"]
VALID_ORIGINS = ["github", "github-enterprise", "github-cloud-app"]
MIGRATABLE_ORIGINS = ["github", "github-enterprise"]
SNYK_V1_API_BASE_URL = "https://snyk.io/api/v1"
SNYK_V1_API_BASE_URL_AU = "https://api.au.snyk.io/v1"
SNYK_V1_API_BASE_URL_EU = "https://api.eu.snyk.io/v1"
SNYK_REST_API_BASE_URL = "https://api.snyk.io/rest"
SNYK_REST_API_BASE_URL_AU = "https://api.au.snyk.io/rest"
SNYK_REST_API_BASE_URL_EU = "https://api.eu.snyk.io/rest"
SNYK_REST_API_VERSION = "2024-05-08"
SNYK_HIDDEN_API_BASE_URL = "https://api.snyk.io/hidden"
SNYK_HIDDEN_API_BASE_URL_AU = "https://api.au.snyk.io/hidden"
SNYK_HIDDEN_API_BASE_URL_EU = "https://api.eu.snyk.io/hidden"
SNYK_HIDDEN_API_VERSION = "2023-04-02~experimental"
SNYK_API_TIMEOUT_DEFAULT = 90

# ===== GLOBALS =====

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
)
state = {"verbose": False}

# ===== METHODS =====


class SnykMigrationFacade:  # pylint: disable=too-many-instance-attributes
    """
    Basic class for handling Snyk API calls and functions for migrating targets to the github cloud app
    """

    def __init__(self, snyk_token: str, tenant: str = "") -> None:
        self.snyk_token = snyk_token
        self.tenant = tenant
        self.rest_api_base_url = SNYK_REST_API_BASE_URL
        self.v1_api_base_url = SNYK_V1_API_BASE_URL

        self.headers = {
            "Authorization": f"token {self.snyk_token}",
            "Content-Type": "application/json",
        }

        self.ignored = []
        self.migrated = []
        self.failed = []
        self.group_organizations = []
        if tenant:
            self.set_base_url_by_tenant(tenant)

    def get_all_group_organizations(self):
        """
        Retrieve all organizations for a Snyk account
        returns: list of organizations
        """

        url = f"{self.v1_api_base_url}/orgs"

        try:
            response = requests.request(
                method="GET",
                url=url,
                headers=self.headers,
                timeout=SNYK_API_TIMEOUT_DEFAULT,
            )
        except requests.ConnectionError:
            print(f"Unable to connect to Snyk API: {url}")
            raise

        if response.status_code != 200:
            raise ValueError(
                f"Unable to retrieve organizations for Snyk account: {vars(response)}"
            )

        response.raise_for_status()

        data = json.loads(response.content)
        self.group_organizations = data["orgs"]
        if not self.group_organizations:
            raise ValueError("No organizations found in Snyk account")

        print(f"Found group organizations: {len(self.group_organizations)}")

    def set_base_url_by_tenant(self, tenant: str):
        """
        Update the base URLs for the Snyk APIs based on the tenant
        """

        print(f"Updating base URLs to tenant: {tenant}")
        if tenant == "au":
            self.rest_api_base_url = SNYK_REST_API_BASE_URL_AU
            self.v1_api_base_url = SNYK_V1_API_BASE_URL_AU
        if tenant == "eu":
            self.rest_api_base_url = SNYK_REST_API_BASE_URL_EU
            self.v1_api_base_url = SNYK_V1_API_BASE_URL_EU

        print(f"REST API Base URL: {self.rest_api_base_url}")
        print(f"V1 API Base URL: {self.v1_api_base_url}")

    def get_org_by_slug(self, org_slug: str):
        """
        Retrieve a Snyk organization by name
        Args:
            org_slug (str): Name of the organization to retrieve
        Returns:
            dict: Snyk organization
        """

        for org in self.group_organizations:
            if org["slug"] == org_slug:
                return org

        return None

    def get_org_by_id(self, org_id: str):
        """
        Retrieve a Snyk organization by ID
        Args:
            org_id (str): ID of the organization to retrieve
        Returns:
            dict: Snyk organization
        """

        for org in self.group_organizations:
            if org["id"] == org_id:
                return org

        return None

    def get_org_integrations(self, org_id):
        """Gets all integrations for a snyk organization

        Args:
            org_id (str): Snyk Organization ID

        Returns:
            dict: _description_
        """
        url = f"{self.v1_api_base_url}/org/{org_id}/integrations"

        try:
            response = requests.request(
                method="GET",
                url=url,
                headers=self.headers,
                timeout=SNYK_API_TIMEOUT_DEFAULT,
            )
        except requests.ConnectionError:
            print(f"Unable to connect to Snyk API: {url}")
            raise

        if response.status_code != 200:
            raise ValueError(
                f"Unable to retrieve integrations for Snyk org: {org_id}: {vars(response)}"
            )

        response.raise_for_status()

        integrations = json.loads(response.content)
        print(f"Found integrations for org ID: {org_id}: {integrations}")
        return integrations

    def get_targets_by_origin(self, org_id: str, origin: str) -> list:
        """Helper function to retrieve all github based targets in an org

        Args:
            org_id (str): Snyk Organization ID

        Returns:
            list: github targets in a snyk org

        """

        print(f"Collecting targets for origin: {origin}")

        targets = []

        params = {
            "version": SNYK_REST_API_VERSION,
            "limit": 100,
            "source_types": [origin],
            "exclude_empty": "false",
        }

        url = f"{self.rest_api_base_url}/orgs/{org_id}/targets"

        while True:
            response = requests.request(
                "GET",
                url,
                headers=self.headers,
                params=params,
                timeout=SNYK_API_TIMEOUT_DEFAULT,
            )

            # print(f"Response: {vars(response)}")
            response.raise_for_status()

            response_json = json.loads(response.content)
            targets.extend(response_json.get("data", []))

            if (
                "next" not in response_json["links"]
                or response_json["links"]["next"] == ""
            ):
                break
            url = f"{self.rest_api_base_url}/{response_json['links']['next']}"

        return targets

    def organize_targets_by_name(self, targets: list) -> dict:
        """
        Helper function to collect target URLs or displaynames from a list of targets
        This allows doing quick lookups for existing targets by URL or if not available, by name

        Args:
            targets (list): List of targets to collect URLs from

        Returns:
            list: List of target URLs
        """
        organized_targets = {"url": [], "display_name": []}
        for target in targets:
            organized_targets["url"].append(target["attributes"]["url"])
            organized_targets["display_name"].append(
                target["attributes"]["display_name"]
            )

        return organized_targets

    def get_migratable_orgs(
        self, migrate_all_orgs: bool, org_id: str = "", org_slug: str = ""
    ) -> list:
        """
        Get a list of organizations to migrate targets for, based on user parameters

        Args:
            migrate_all_orgs: bool: migrate all orgs in the group
            org_id: str: snyk org id (optional)
            org_slug: str: snyk org slug (optional)
        Returns:
            list: orgs to migrate
        """

        if migrate_all_orgs:
            return self.group_organizations

        if org_id:
            org = self.get_org_by_id(org_id)
            if not org:
                raise ValueError(f"Organization not found: {org_id}")
            print(f"Found organization by ID {org_id}: {org}")
            return [org]

        if org_slug:
            org = self.get_org_by_slug(org_slug)
            if not org:
                raise ValueError(f"Organization not found: {org_slug}")
            print(f"Found organization by slug {org_slug}: {org}")
            return [org]

        raise ValueError("No organization(s) found")

    def find_migratable_targets(
        self, org_id: str, org_integrations: dict, allowed_origins: list
    ) -> list:
        """
        Locate migratable targets in a Snyk organization
        It's possible for an organization to have the same target already imported via
        the github-cloud-app integration, this function will filter out those targets.

        Args:
        org (dict): Snyk Organization object
        org_integrations (dict): Snyk integrations for an organization collected through get_org_integrations
        Return: a list of valid targets to migrate
        """

        if "github-cloud-app" not in org_integrations:
            print(
                "No GitHub Cloud App integration detected, please set up before migrating GitHub or GitHub Enterprise targets"
            )
            raise ValueError(
                f"github-cloud-app integration not configured to org ID: {org_id}"
            )

        github_cloud_targets = self.get_targets_by_origin(org_id, "github-cloud-app")
        organized_cloud_targets = self.organize_targets_by_name(github_cloud_targets)

        if github_cloud_targets:
            print(f"github-cloud-app targets for {org_id}:")
            print(organized_cloud_targets)

        print(f"Searching for targets in allowed origins: {allowed_origins}")

        github_targets = []
        for i_origin in org_integrations:
            if i_origin not in allowed_origins:
                continue
            github_targets.extend(self.get_targets_by_origin(org_id, i_origin))

        migratable_targets = []
        for gh_t in github_targets:
            url = gh_t["attributes"]["url"]
            display_name = gh_t["attributes"]["display_name"]
            is_private = gh_t["attributes"]["is_private"]

            # don't migrate public targets
            if not is_private:
                print(
                    f"Skipping public target: {display_name} in org: {org_id}, not private"
                )
                self.ignored.append(gh_t)
                continue

            # don't migrate targets that are already in github-cloud-app
            if url and url in organized_cloud_targets["url"]:
                print(f"There's already a github-cloud-app target for: {url}, skipping")
                self.ignored.append(gh_t)
                continue

            if display_name in organized_cloud_targets["display_name"]:
                print(
                    f"There's already a github-cloud-app target for: {display_name}, skipping"
                )
                self.ignored.append(gh_t)
                continue

            # if github_organizations is set, only migrate targets from those organizations
            for gh_org in github_organizations:
                migratable_targets.append(gh_t)
            migratable_targets.append(gh_t)

        return migratable_targets

    def parse_github_cloud_organization_from_target(self, target):
        """
        Attempt to parse the GitHub organization name from a target object either through
        the URL or the display name attributes
        Args:
            target (dict): Snyk target object
        Returns:
            str: GitHub organization name
        """
        url = target["attributes"]["url"]
        display_name = target["attributes"]["display_name"]

        if url and url.startswith("https://github.com"):
            return url.lstrip("https://github.com/").split("/")[0]

        return display_name.split("/")[0]

    def migrate_target_to_github_cloud_app(self, org_id: str, target: dict):
        """Mgrate a target to github-cloud-app using the hidden API

        Args:
            org_id (str): Snyk Organization ID
            target (dict): Target to be migrated
        """

        headers = {
            "Content-Type": "application/vnd.api+json",
            "Authorization": f"token {self.snyk_token}",
        }

        url = f"{self.rest_api_base_url}/orgs/{org_id}/targets/{target['id']}?version={SNYK_HIDDEN_API_VERSION}"

        body = json.dumps(
            {
                "data": {
                    "id": f"{target['id']}",
                    "attributes": {"source_type": "github-cloud-app"},
                }
            }
        )

        response = requests.request(
            "PATCH",
            url,
            headers=headers,
            data=body,
            timeout=SNYK_API_TIMEOUT_DEFAULT,
        )

        response.raise_for_status()
        return response

    def migrate_targets(self, org_id: str, targets: list):
        """Helper function to migrate list of github and github-enterprise targets to github-cloud-app

        Args:
            org_id (str): Snyk Organization ID
            targets (list): List of targets to be migrated
        """

        for target in targets:
            try:
                res = self.migrate_target_to_github_cloud_app(org_id, target)
                if res.status_code == 200:
                    print(
                        f"Migrated target: {target['id']} {target['attributes']['display_name']} to github-cloud-app"
                    )
                    self.migrated.append(target)
                else:
                    print(f"Error migrating target: {target}: {vars(res)}")
                    self.failed.append(target)
            except requests.HTTPError as exc:
                print(f"ERROR: Failed to migrate target: {target}: {exc}")
                self.failed.append(target)

    @staticmethod
    def verify_org_integrations(integrations: dict, origin: str):
        """Helper function to make sure the Snyk Organization has the relevant github integrations set up

        Args:
            integrations (dict): Snyk integrations for an organization collected through get_org_integrations
            origin (str): Origin of the integration to verify

        Returns:
            bool: _description_
        """

        if "github-cloud-app" not in integrations:
            print(
                "No GitHub Cloud App integration detected, please set up before migrating GitHub or GitHub Enterprise targets"
            )
            raise ValueError("github-cloud-app integration not configured")

        if origin not in integrations:
            print(f"No {origin} integration detected")
            return False

        return True

    @staticmethod
    def log_target(target: dict):
        """
        Logging helper for targets
        Args: target (dict): Target to be logged
        """
        origin = target["relationships"]["integration"]["data"]["attributes"][
            "integration_type"
        ]
        t_id = target["id"]
        name = target["attributes"]["display_name"]
        url = target["attributes"]["url"]
        return f"ID: {t_id}, Name: {name}, Origin: {origin}, URL: {url}"

    def show_results(self):
        """Prints out the results of the migration"""
        for target in self.migrated:
            print(f"Migrated: {self.log_target(target)}")

        for target in self.failed:
            print(f"Failed: {self.log_target(target)}")

        for target in self.ignored:
            print(f"Ignored: {self.log_target(target)}")

        print(f"Migrated targets: {len(self.migrated)}")
        print(f"Failed targets: {len(self.failed)}")
        print(f"Ignored targets: {len(self.ignored)}")

    def dry_run_targets(self, targets):
        """Print targets that would get migrated to GitHub App integration without migrating them

        Args:
            targets: List of targets to be logged
        """
        for target in targets:
            self.migrated.append(target)
        self.show_results()


@app.command()
def main(  # pylint: disable=too-many-arguments, too-many-branches, too-many-locals
    snyk_token: Annotated[
        str,
        typer.Option(
            help="Snyk API token with admin access to the orgs you are migrating, or set as environment variable",
            envvar="SNYK_TOKEN",
        ),
    ],
    origin: Annotated[
        str,
        typer.Option(
            help=f"Target origins to migrate, one of {MIGRATABLE_ORIGINS}",
            envvar="SNYK_ORIGIN",
        ),
    ] = "",
    migrate_all_origins: Annotated[
        bool,
        typer.Option(help="Migrate both github and github-enterprise targets"),
    ] = False,
    migrate_all_orgs: Annotated[
        bool,
        typer.Option(
            help="Migrate all organizations in Snyk group, default is to migrate a single organization"
        ),
    ] = False,
    org_id: Annotated[
        str,
        typer.Option(
            help="ID of Organization in Snyk you wish to migrate targets to GitHub App",
            envvar="SNYK_ORG_ID",
        ),
    ] = "",
    org_slug: Annotated[
        str,
        typer.Option(
            help="Slug of organization in Snyk you wish to migrate targets to GitHub App",
            envvar="SNYK_ORG_SLUG",
        ),
    ] = "",
    tenant: Annotated[
        str,
        typer.Option(
            help="Defaults to US tenant, add 'eu' or 'au' if required",
            envvar="SNYK_TENANT",
        ),
    ] = "",
    dry_run: Annotated[
        bool,
        typer.Option(help="Print names of targets to be migrated without migrating"),
    ] = True,
    verbose: bool = False,
):
    """CLI Tool to help you migrate your targets from the GitHub or GitHub Enterprise integration to the new GitHub App Integration"""

    # ===== VALIDATE ARGUMENTS =====

    if verbose:
        state["verbose"] = True

    if tenant not in VALID_TENANTS:
        raise typer.BadParameter(f"--tenant must be one of {VALID_TENANTS}")

    if migrate_all_orgs is False and not (org_id or org_slug):
        raise typer.BadParameter(
            "--org-id or --org-slug must be provided for single org migration if --migrate-all-orgs is false"
        )

    if migrate_all_origins is False and not origin:
        raise typer.BadParameter(
            "--origin must be provided when --migrate-all-origins is false"
        )

    if origin not in MIGRATABLE_ORIGINS:
        raise typer.BadParameter(f"--origin must be one of {MIGRATABLE_ORIGINS}")

    # ===== MAIN LOGIC =====

    if migrate_all_origins:
        allowed_origins = MIGRATABLE_ORIGINS
    else:
        allowed_origins = [origin]

    snyk = SnykMigrationFacade(snyk_token, tenant=tenant)

    try:
        snyk.get_all_group_organizations()
        migratable_orgs = snyk.get_migratable_orgs(
            migrate_all_orgs=migrate_all_orgs, org_id=org_id, org_slug=org_slug
        )
        try:
            for org in migratable_orgs:
                slug = org["slug"]
                print(f"Migrating organization: {slug}")
                org_id = org["id"]
                org_integrations = snyk.get_org_integrations(org_id)
                migratable_targets = snyk.find_migratable_targets(
                    org_id, org_integrations, allowed_origins=allowed_origins
                )
                if not migratable_targets:
                    print("No targets to migrate for org: {slug}")
                    continue
                if dry_run:
                    snyk.dry_run_targets(migratable_targets)
                    continue
                snyk.migrate_targets(org_id, migratable_targets)
        except ValueError as exc:
            print(f"Failed to migrate: {org_id}: {exc}")
            raise
    except (requests.ConnectionError, requests.HTTPError) as exc:
        raise ValueError(f"Failed to migrate targets: {exc}") from exc


def run():
    """Run the defined typer CLI app"""
    try:
        app()
    except ValueError as exc:
        print(f"Error: {exc}")
