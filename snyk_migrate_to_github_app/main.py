"""
Primary logic for the CLI Tool
"""

# ===== IMPORTS =====

import json
import logging
import os
from http import HTTPStatus
from logging.config import dictConfig

import coloredlogs  # pylint: disable=unused-import
import requests
import typer
from typing_extensions import Annotated

FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s:%(lineno)d] %(message)s"

LEVEL = "INFO"
if os.getenv("DEBUG"):
    LEVEL = "DEBUG"

logging_config = {
    "version": 1,
    "formatters": {
        "default": {
            "()": "coloredlogs.ColoredFormatter",
            "format": FORMAT,
        },
        "file": {
            "format": FORMAT,
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "default",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "snyk-migrate-to-github-app.log",
            "mode": "a",
            "formatter": "file",
        },
    },
    "root": {
        "level": LEVEL,
        "handlers": ["console", "file"],
        "datefmt": "%Y-%m-%d %H:%M:%S",
    },
}

dictConfig(logging_config)
logger = logging.getLogger(__name__)

# Uncomment these to debug HTTP requests
# import http.client as http_client
# http_client.HTTPConnection.debuglevel = 1


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
        self.hidden_api_base_url = SNYK_HIDDEN_API_BASE_URL
        self.v1_api_base_url = SNYK_V1_API_BASE_URL

        self.headers = {
            "Authorization": f"token {self.snyk_token}",
            "Content-Type": "application/json",
        }

        self.results = {
            "migrated": {},
            "failed": {},
            "ignored": {},
        }
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
        except requests.ConnectionError as exc:
            logger.error("Unable to connect to Snyk API: %s -> %s", url, exc)
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

        logger.info("Found group organizations: %s", len(self.group_organizations))

    def set_base_url_by_tenant(self, tenant: str):
        """
        Update the base URLs for the Snyk APIs based on the tenant
        """

        logger.info("Updating base URLs to tenant: %s", tenant)
        if tenant == "au":
            self.rest_api_base_url = SNYK_REST_API_BASE_URL_AU
            self.v1_api_base_url = SNYK_V1_API_BASE_URL_AU
            self.hidden_api_base_url = SNYK_HIDDEN_API_BASE_URL_AU
        if tenant == "eu":
            self.rest_api_base_url = SNYK_REST_API_BASE_URL_EU
            self.v1_api_base_url = SNYK_V1_API_BASE_URL_EU
            self.hidden_api_base_url = SNYK_HIDDEN_API_BASE_URL_EU

        logger.info("REST API Base URL: %s", self.rest_api_base_url)
        logger.info("V1 API Base URL %s:", self.v1_api_base_url)

    def get_org_by_slug(self, org_slug: str) -> dict:
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

        return {}

    def get_org_by_id(self, org_id: str) -> dict:
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

        return {}

    def get_org_integrations(self, org_id: str) -> dict:
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
            logger.error("Unable to connect to Snyk API: %s", url)
            raise

        if response.status_code != 200:
            raise ValueError(
                f"Unable to retrieve integrations for Snyk org: {org_id}: {vars(response)}"
            )

        response.raise_for_status()

        integrations = json.loads(response.content)
        logger.info("Found integrations for org ID: %s: %s", org_id, integrations)
        return integrations

    def get_targets_by_origin(self, org_id: str, origin: str) -> list:
        """Helper function to retrieve all github based targets in an org

        Args:
            org_id (str): Snyk Organization ID

        Returns:
            list: github targets in a snyk org

        """

        logger.info("Collecting targets for origin: %s", origin)

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

    def organize_targets_by_name_and_url(self, targets: list) -> dict:
        """
        Helper function to collect target URLs or displaynames from a list of targets
        This allows doing quick lookups for existing targets by URL or if not available,
        by name

        Args:
            targets (list): List of targets to collect URLs from

        Returns:
            list: List of target URLs
        """
        organized_targets = {}
        for target in targets:
            t_url = target["attributes"]["url"]
            t_name = target["attributes"]["display_name"]
            organized_targets[t_name] = t_url

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
            logger.info("Found organization by ID: %s: %s", org_id, org)
            return [org]

        if org_slug:
            org = self.get_org_by_slug(org_slug)
            if not org:
                raise ValueError(f"Organization not found: {org_slug}")
            logger.info("Found organization by slug: %s: %s", org_slug, org)
            return [org]

        raise ValueError("No organization(s) found")

    def find_migratable_targets(  # pylint: disable=too-many-locals
        self,
        org_id: str,
        org_integrations: dict,
        allowed_origins: list,
        github_organizations: list,
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
            logger.info(
                "No GitHub Cloud App integration detected, please set up before migrating GitHub or GitHub Enterprise targets"
            )
            raise ValueError(
                f"github-cloud-app integration not configured to org ID: {org_id}"
            )

        github_cloud_targets = self.get_targets_by_origin(org_id, "github-cloud-app")
        organized_cloud_targets = self.organize_targets_by_name_and_url(
            github_cloud_targets
        )

        if github_cloud_targets:
            logger.info("github-cloud-app targets for: %s", org_id)
            logger.info(organized_cloud_targets)

        logger.info("Searching for targets in allowed origins: %s", allowed_origins)

        github_targets = []
        for i_origin in org_integrations:
            if i_origin not in allowed_origins:
                continue
            github_targets.extend(self.get_targets_by_origin(org_id, i_origin))

        migratable_targets = []
        for gh_t in github_targets:
            url = gh_t["attributes"]["url"]
            _id = gh_t["id"]
            display_name = gh_t["attributes"]["display_name"]
            is_private = gh_t["attributes"]["is_private"]
            gh_org = self.parse_github_cloud_organization_from_target(gh_t)

            # don't migrate public targets
            if not is_private:
                logger.info(
                    "Skipping public target: %s in org: %s, not private",
                    display_name,
                    org_id,
                )
                self.results["ignored"][_id] = {
                    "target": gh_t,
                    "reason": "public target",
                }
                continue

            if display_name in organized_cloud_targets:
                logger.info(
                    "There's already a github-cloud-app target for: %s, skipping",
                    display_name,
                )
                self.results["ignored"][_id] = {
                    "target": gh_t,
                    "reason": "conflicting github-cloud-app target",
                }
                continue

            for _, t_url in organized_cloud_targets:
                if url == t_url:
                    logger.info(
                        "There's already a github-cloud-app target for: %s, skipping",
                        url,
                    )
                    self.results["ignored"][_id] = {
                        "target": gh_t,
                        "reason": "conflicting github-cloud-app target",
                    }
                    continue

            # if github_organizations is set, only migrate targets from those organizations
            if github_organizations and gh_org not in github_organizations:
                logger.info(
                    "Target not in specified github organizations: %s not in %s",
                    gh_org,
                    github_organizations,
                )
                self.results["ignored"][_id] = {
                    "target": gh_t,
                    "reason": "not in specified github organizations",
                }
                continue
            migratable_targets.append(gh_t)

        return migratable_targets

    def parse_github_cloud_organization_from_target(self, target: dict) -> str:
        """
        Attempt to parse the GitHub organization name from a target object either through
        the URL or the display name attributes
        Args:
            target (dict): Snyk target object
        Returns:
            str: GitHub organization name
        """
        url = target["attributes"].get("url")
        display_name = target["attributes"]["display_name"]

        logger.info("Name: %s, Target URL:%s", display_name, url)
        if url and url.startswith("http"):
            if not url.startswith("https://github.com"):
                logger.info("URL not pointing to github.com, skipping: %s", url)
                return ""
            return url.replace("https://github.com/", "").split("/")[0]

        if "/" not in display_name:
            return ""

        # best guess
        return display_name.split("/")[0]

    def migrate_target_to_github_cloud_app(
        self, org_id: str, target: dict
    ) -> requests.Response:
        """Mgrate a target to github-cloud-app using the hidden API

        Args:
            org_id (str): Snyk Organization ID
            target (dict): Target to be migrated
        """

        headers = {
            "Content-Type": "application/vnd.api+json",
            "Authorization": f"token {self.snyk_token}",
        }

        url = f"{self.hidden_api_base_url}/orgs/{org_id}/targets/{target['id']}?version={SNYK_HIDDEN_API_VERSION}"

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

        return response

    def migrate_targets(self, org_id: str, targets: list):
        """Helper function to migrate list of github and github-enterprise targets to github-cloud-app

        Args:
            org_id (str): Snyk Organization ID
            targets (list): List of targets to be migrated
        """

        for target in targets:
            t_id = target["id"]
            try:
                res = self.migrate_target_to_github_cloud_app(org_id, target)
                if res.status_code == HTTPStatus.OK:
                    logger.info(
                        "Migrated target: %s - %s to github-cloud-app",
                        t_id,
                        target["attributes"]["display_name"],
                    )
                    self.results["migrated"][t_id] = {
                        "target": target,
                        "reason": "OK",
                    }
                elif res.status_code == HTTPStatus.CONFLICT:
                    logger.warning(
                        "Target already migrated: %s: %s",
                        target["id"],
                        target["attributes"],
                    )
                    self.results["ignored"][t_id] = {
                        "target": target,
                        "reason": "already migrated",
                    }
                else:
                    logger.warning("Error migrating target: %s: %s", target, vars(res))
                    self.results["failed"][t_id] = {
                        "target": target,
                        "reason": vars(res),
                    }
            except requests.HTTPError as exc:
                logger.error("ERROR: Failed to migrate target: %s: %s", target, exc)
                self.results["failed"][t_id] = {
                    "target": target,
                    "reason": exc,
                }

    @staticmethod
    def verify_org_integrations(integrations: dict, origin: str) -> bool:
        """Helper function to make sure the Snyk Organization has the relevant github integrations set up

        Args:
            integrations (dict): Snyk integrations for an organization collected through get_org_integrations
            origin (str): Origin of the integration to verify

        Returns:
            bool: _description_
        """

        if "github-cloud-app" not in integrations:
            logger.info(
                "No GitHub Cloud App integration detected, please set up before migrating GitHub or GitHub Enterprise targets"
            )
            raise ValueError("github-cloud-app integration not configured")

        if origin not in integrations:
            logger.info("No %s integration detected", origin)
            return False

        return True

    @staticmethod
    def log_result(result: dict) -> str:
        """
        Logging helper for targets
        Args: target (dict): Target to be logged
        """
        target = result["target"]
        reason = result["reason"]
        origin = target["relationships"]["integration"]["data"]["attributes"][
            "integration_type"
        ]
        t_id = target["id"]
        name = target["attributes"]["display_name"]
        url = target["attributes"]["url"]
        return f"ID: {t_id}, Name: {name}, Origin: {origin}, URL: {url}, Reason: {reason.capitalize()}"

    def show_results(self):
        """Prints out the results of the migration"""
        for topic in self.results:  # pylint: disable=consider-using-dict-items
            for _, result in self.results[topic].items():
                logger.info("%s: %s", topic.capitalize(), self.log_result(result))

        for topic in self.results:  # pylint: disable=consider-using-dict-items
            logger.info("%s: targets: %s", topic.capitalize(), len(self.results[topic]))

    def dry_run_targets(self, targets):
        """Print targets that would get migrated to GitHub App integration without migrating them

        Args:
            targets: List of targets to be logged
        """
        for target in targets:
            self.results["migrated"][target["id"]] = {
                "target": target,
                "reason": "dry-run",
            }
        self.show_results()


@app.command()
def main(  # pylint: disable=too-many-arguments, too-many-branches, too-many-locals, dangerous-default-value
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
    # A large enterprise may have more than one github organization, the cloud app integration
    # may be available in only a subset of these organizations. This option allows you to specify
    # which github organizations to migrate targets from.
    github_organizations: Annotated[
        list[str],
        typer.Option(
            help="GitHub organization name to migrate (default all), pass multiple by repeating this argument",
        ),
    ] = [],
    tenant: Annotated[
        str,
        typer.Option(
            help="Defaults to US tenant, add 'eu' or 'au' if required",
            envvar="SNYK_TENANT",
        ),
    ] = "",
    deploy: Annotated[
        bool,
        typer.Option(help="Deploy changes for real, defaults to dry-run"),
    ] = False,
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

    if deploy is False:
        logger.warning("DRY-RUN MODE: NO CHANGES WILL BE MADE")
    else:
        logger.warning("DEPLOY MODE: MIGRATING FOR REAL!")

    try:
        snyk.get_all_group_organizations()
        migratable_orgs = snyk.get_migratable_orgs(
            migrate_all_orgs=migrate_all_orgs, org_id=org_id, org_slug=org_slug
        )
        try:
            migratable_targets = []
            for org in migratable_orgs:
                slug = org["slug"]
                logger.info("Migrating snyk organization: %s", slug)
                org_id = org["id"]
                org_integrations = snyk.get_org_integrations(org_id)
                org_migratable_targets = snyk.find_migratable_targets(
                    org_id,
                    org_integrations,
                    allowed_origins=allowed_origins,
                    github_organizations=github_organizations,
                )
                if not org_migratable_targets:
                    logger.warning("No targets to migrate for org: %s", slug)
                    continue
                migratable_targets.extend(org_migratable_targets)

            if deploy is True:
                snyk.migrate_targets(org_id, migratable_targets)
            else:
                snyk.dry_run_targets(migratable_targets)

        except ValueError as exc:
            logger.error("Failed to migrate: %s: %s", org_id, exc)
            raise
    except (requests.ConnectionError, requests.HTTPError) as exc:
        raise ValueError(f"Failed to migrate targets: {exc}") from exc


def run():
    """Run the defined typer CLI app"""
    try:
        app()
    except ValueError as exc:
        logger.error(exc)
