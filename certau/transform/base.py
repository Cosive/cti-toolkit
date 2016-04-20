import logging
import pprint
import copy

from cybox import EntityList
from cybox.core import Object
from cybox.common import ObjectProperties
from stix.extensions.marking.tlp import TLPMarkingStructure


class StixTransform(object):
    """Base class for transforming a STIX package to an alternate format.

    This class provides helper functions for processing
    :py:class:`STIXPackage<stix.core.stix_package.STIXPackage>` elements.
    This class should be extended by other classes that
    transform STIX packages into alternate formats.

    The default constructor processes a STIX package to initialise
    self._observables, a :py:class:`dict` keyed by object type.
    Each entry contains a list :py:class:`list` of :py:class:`dict` objects
    with three keys: 'id', 'observable', and 'fields', containing the
    observable ID, the :py:class:`Observable<cybox.core.observable.Observable>`
    object itself, and extracted fields, respectively.

    Args:
        package: the STIX package to transform

    Attributes:
        OBJECT_FIELDS: a :py:class:`dict` of supported Cybox object types
            and fields ('properties'). The dictionary is keyed by Cybox object
            type string (see :py:func:`_observable_object_type`) with each
            entry containing a list of field names from that object that will
            be utilised during the transformation.

            Field names may reference sub-objects using dot notation.
            For example the Cybox EmailMessage class contains a `header` field
            referring to an EmailHeader object which contains a `to` field.
            This field can be referenced using the notation `header.to`.

            If OBJECT_FIELDS evaluates to False (e.g. empty dict()), it is
            assumed all object types are supported.

        OBJECT_CONSTRAINTS: a :py:class:`dict` of constraints on the
            supported object types based on 'categories' associated with that
            type. For example, the Cybox Address object uses the field
            `category` to distinguish between IPv4, IPv6 and even email
            addresses. Like OBJECT_FIELDS, the dictionary is keyed by object
            type. Each entry contains a dictionary keyed by field name,
            containing a list of values, or categories, (for that field name)
            that are supported by the transform.

            Note. Does not support the expression of more complex constraints,
            for example combining different categories.

        STRING_CONDITION_CONSTRAINT: a :py:class:`list` of string condition
            values supported by the transform. For example, some transforms
            may not support 'FitsPattern' or 'StartsWith' string condition
            values. Use this to list the supported values. Note the values
            are strings, even 'None'.
    """

    # Class constants - see descriptions above
    OBJECT_FIELDS = dict()
    OBJECT_CONSTRAINTS = dict()
    STRING_CONDITION_CONSTRAINT = list()

    def __init__(self, package):
        self._package = package
        self._observables = self._observables_for_package(package)

        # Initialise the logger
        self._logger = logging.getLogger()
        self._logger.debug('%s object created', self.__class__.__name__)

    # ##### Helpers for extracting various STIX package elements. #####

    def package_title(self, default=''):
        """Retrieves the STIX package title (str) from the header."""
        if self._package.stix_header and self._package.stix_header.title:
            return self._package.stix_header.title.encode('utf-8')
        else:
            return default

    def package_description(self, default=''):
        """Retrieves the STIX package description (str) from the header."""
        if self._package.stix_header and self._package.stix_header.description:
            return self._package.stix_header.description.value.encode('utf-8')
        else:
            return default

    def package_tlp(self, default='AMBER'):
        """Retrieves the STIX package TLP (str) from the header."""
        if self._package.stix_header:
            handling = self._package.stix_header.handling
            if handling and handling.markings:
                for marking_spec in handling.markings:
                    for marking_struct in marking_spec.marking_structures:
                        if isinstance(marking_struct, TLPMarkingStructure):
                            return marking_struct.color
        return default

    # ### Internal methods for processing observables, objects and properties.

    @staticmethod
    def _observable_properties(observable):
        """Retrieves an observable's object's properties.

        Args:
            observable: a :py:class:`cybox.Observable` object

        Returns:
            :py:class:`cybox.ObjectProperties`: the properties from the
                observable's object (if they exist), otherwise None.
        """
        if (isinstance(observable.object_, Object) and
                isinstance(observable.object_.properties, ObjectProperties)):
            return observable.object_.properties
        else:
            return None

    @staticmethod
    def _observable_object_type(observable):
        """Determine the object type of an observable's object.

        Observable object's properties are Cybox object types which extend
        the ObjectProperties class. The class name for these objects is
        used to represent the object type.

        Args:
            observable: a :py:class:`cybox.Observable` object

        Returns:
            str: a string representation of the observable's object properties
                type, or None if observable contains no properties.
        """
        properties = StixTransform._observable_properties(observable)
        return properties.__class__.__name__ if properties else None

    @staticmethod
    def _condition_key_for_field(field):
        """Dictionary key used for storing the string condition of a field."""
        return field + '_condition'

    @classmethod
    def _observables_for_package(cls, package):
        """Extract observables from a STIX package.

        Collects observables from a STIX package and groups them by object
        type. Only observables with an ID and containing a Cybox object are
        returned. Results are returned in a dictionary keyed by object
        type - see :py:func:`_observable_object_type`.

        If OBJECT_FIELDS are specified only observables containing the
        object types listed will be returned, and only those with at
        least one of the listed fields containing a non-trivial value.
        OBJECT_CONSTRAINTS and STRING_CONDITION_CONSTRAINT are also applied.

        If no OBJECT_FIELDS are specified no constraints are applied and all
        identified observables are returned.

        Observables are sought from the following locations:

            - the root of the STIX package
            - within Indicator objects (where the indicators are in the package
              root)
            - within ObservableComposition objects found in either of the two
              previous locations

        Args:
            package: a :py:class:`stix:STIXPackage` object

        Returns:
            dict: a dictionary of valid observables, keyed by object type
                (See description above). May be empty.
        """

        def _add_observables(new_observables):
            for observable in new_observables:
                if observable.observable_composition is not None:
                    _add_observables(
                        observable.observable_composition.observables
                    )
                else:
                    object_type = cls._observable_object_type(observable)
                    if (observable.id_ is not None and
                            observable.id_ not in observable_ids and
                            object_type is not None):
                        object_type = cls._observable_object_type(observable)
                        if object_type in cls.OBJECT_FIELDS.keys():
                            fields = cls._field_values_for_observable(
                                observable
                            )
                            if not fields:
                                continue
                        elif not cls.OBJECT_FIELDS:
                            fields = None
                        else:
                            continue
                        if object_type not in observables:
                            observables[object_type] = []
                        new_observable = dict(
                            id=observable.id_,
                            observable=observable,
                            fields=fields,
                        )
                        observables[object_type].append(new_observable)
                        observable_ids.append(observable.id_)

        # Look for observables in the package root and in indicators
        observable_ids = []
        observables = dict()
        if package.observables:
            _add_observables(package.observables)
        if package.indicators:
            for i in package.indicators:
                if i.observables:
                    _add_observables(i.observables)
        return observables

    @classmethod
    def _field_values_for_observable(cls, observable):
        """Collects property field values for an observable."""
        object_type = cls._observable_object_type(observable)
        fields = list(cls.OBJECT_FIELDS[object_type])

        # Add any fields required for constraint checking
        if object_type in cls.OBJECT_CONSTRAINTS.keys():
            for field in cls.OBJECT_CONSTRAINTS[object_type]:
                if field not in fields:
                    fields.append(field)

        # Get field values
        values = []
        properties = cls._observable_properties(observable)
        cls._field_values_for_entity(values, properties, fields)

        # Check constraints
        if object_type in cls.OBJECT_CONSTRAINTS.keys():
            for field in cls.OBJECT_CONSTRAINTS[object_type]:
                for value in values:
                    # Multiple constraints are combined with an implied 'AND'
                    # (i.e. all of the constraints must be satisfied)
                    if (field not in value or value[field] not in
                            cls.OBJECT_CONSTRAINTS[object_type][field]):
                        values.remove(value)
                        break
                    # Remove the constraint field if not needed
                    if field not in cls.OBJECT_FIELDS[object_type]:
                        del value[field]
        return values

    @classmethod
    def _field_values_for_entity(cls, values, entity, fields, first_part=''):
        """Returns requested field values from a cybox.Entity object."""

        def _first_parts(fields):
            """Get the bits on the left of the first dot in the field names.
            """
            first_parts = set()
            for field in fields:
                parts = field.split('.')
                first_parts.add(parts[0])
            return first_parts

        def _next_parts(fields, field):
            """Get the next parts for this field."""
            next_parts = set()
            first_part = field + '.'
            for field in fields:
                if field.startswith(first_part):
                    next_parts.add(field[len(first_part):])
            return next_parts

        def _convert_to_str(value):
            if isinstance(value, basestring):
                return value.encode('utf-8')
            else:
                return pprint.pformat(value)

        def _get_value_condition(value):
            """Set the condition value to '-' if the field doesn't have a
            condition attribute to allow us to differentiate it from a value
            that does contain a condition attribute, but its value is None.
            """
            condition = getattr(value, 'condition', '-')
            value = getattr(value, 'value', value)
            return (_convert_to_str(value), _convert_to_str(condition))

        def _add_value_to_dict(dict_, value, field):
            value, condition = _get_value_condition(value)
            if value and (not cls.STRING_CONDITION_CONSTRAINT or
                          condition in cls.STRING_CONDITION_CONSTRAINT or
                          condition == '-'):
                dict_[field] = value
                if condition != '-':
                    c_field = cls._condition_key_for_field(field)
                    dict_[c_field] = condition

        def _add_value_to_values(values, value, field):
            """Add value and condition (if present) to results."""
            if values:
                for dict_ in values:
                    _add_value_to_dict(dict_, value, field)
            else:
                # First entry
                dict_ = dict()
                _add_value_to_dict(dict_, value, field)
                if dict_:
                    values.append(dict_)

        for field in _first_parts(fields):
            full_first_part = first_part + '.' + field if first_part else field
            next_parts = _next_parts(fields, field)
            value = getattr(entity, field, None)

            if isinstance(value, (list, EntityList)):
                values_copy = copy.deepcopy(values)
                first = True
                for item in value:
                    v_list = values if first else copy.deepcopy(values_copy)
                    if next_parts:
                        cls._field_values_for_entity(v_list, item, next_parts,
                                                     full_first_part)
                    else:
                        _add_value_to_values(v_list, item, full_first_part)
                    if not first:
                        values.extend(v_list)
                    else:
                        first = False
            elif value:
                if next_parts:
                    cls._field_values_for_entity(values, value, next_parts,
                                                 full_first_part)
                else:
                    _add_value_to_values(values, value, full_first_part)
