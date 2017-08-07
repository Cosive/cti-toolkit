
from stix.extensions.marking import ais

from .helpers import dereference_observables

def ais_refactor(package, proprietary, consent, color, organisation, industry,
                 country, admin_area):
    """Refactor a STIX package to meet AIS requirements."""
    # Add an AIS Marking to the header
    # Note add_ais_marking() removes existing markings
    ais.add_ais_marking(
        stix_package=package,
        proprietary=proprietary,
        consent=consent,
        color=color,
        country_name_code=country,
        industry_type=industry,
        admin_area_name_code=admin_area,
        organisation_name=organisation,
        country_name_code_type='ISO-3166-1_alpha-2',
        admin_area_name_code_type='ISO-3166-2',
    )
    # Dereference observables
    dereference_observables(package)
    # Remove the observables from the root of the package
    package.observables = None
