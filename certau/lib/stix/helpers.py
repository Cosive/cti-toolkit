from __future__ import absolute_import

from stix.extensions.marking.tlp import TLPMarkingStructure

TLP_COLOURS = ["WHITE", "GREEN", "AMBER", "RED"]

def package_time(package):
    if package.stix_header:
        info_source = package.stix_header.information_source
        if info_source and info_source.time and info_source.time.produced_time:
            return info_source.time.produced_time.value
    if package.timestamp:
        return package.timestamp
    return None

def package_title(package):
    """Retrieves the STIX package title (str) from the header."""
    if package.stix_header and package.stix_header.title:
        return str(package.stix_header.title)
    else:
        return None

def package_description(package):
    """Retrieves the STIX package description (str) from the header."""
    if package.stix_header and package.stix_header.description:
        return str(package.stix_header.description)
    else:
        return None

def package_tlp(package):
    """Retrieves the STIX package TLP (str) from the header."""
    if package.stix_header:
        handling = package.stix_header.handling
        if handling and handling.marking:
            for marking_spec in handling.marking:
                for marking_struct in marking_spec.marking_structures:
                    if isinstance(marking_struct, TLPMarkingStructure):
                        return str(marking_struct.color)
    return None

def dereference_observables(package):
    # Build a dictionary for looking up package level observables
    root_observables = {}
    for observable in package.observables:
        if observable.id_ is not None:
            root_observables[observable.id_] = observable
    # Dereference observables in indicators
    for indicator in package.indicators:
        observables = []
        for observable in indicator.observables:
            if observable.idref is None:
                observables.append(observable)
            elif observable.idref in root_observables:
                observables.append(root_observables[observable.idref])
            else:
                raise Exception('unable to dereference observable')
        # Reset the indicator's observables
        if len(observables) == 1:  # Handle bug in python-stix
            indicator.observables = observables[0]
        elif len(observables) > 1:
            indicator.observables = observables
