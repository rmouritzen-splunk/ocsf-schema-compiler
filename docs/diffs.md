# Differences between ocsf-server v3 compile and ocsf-schema-compiler
This document covers the differences with the ocsf-server v3 compiler and the ocsf-schema-compiler output. We will refer to the ocsf-server v3 compiler as the "legacy compiler" with its output as the "legacy format", and the ocsf-schema-compiler as the "new compiler" with its output as the "new format".

## Legacy exported schema vs new format
The ocsf-server's `/export/schema` format does not return all details, requiring use of various `/api` endpoints to retrieve the entire schema. The new format puts everything together.

The new format has the following:
```json5
{
    "categories": {},
    "dictionary": {},
    "classes": {},
    "objects": {},
    "classes": {},
    "profiles": {},
    "extensions": {},
    "version": "<major>.<minor>.<patch>",
    "compile_version": 1, // currently always 1
}
```

The dictionary format is following:
```json5
{
    "name": "dictionary",
    "caption": "Attribute Dictionary",
    "description": "<full description>",
    "attributes": {}, // the attribute information
    "types": {
        "caption": "Data Types",
        "description": "<full description>",
        "attributes": {}, // the actual type information
    }
}
```

For reference, the legacy exported schema has the following top-level structure:
```json5
{
  "base_event": {},
  "classes": {},  // includes "base_event"
  "object": {},
  "dictionary_attributes": {}, // equivalent to the new schema at dictionary.attributes
  "types": {},  // dictionary types; equivalent to the new schema at dictionary.types.attributes
  "version": "<major>.<minor>.<patch>"
}
```

The main differences at this level are:
- The addition of `compile_version` with value 1. The legacy schema has an implied version of 0.
- The addition of `categories`, `profiles`, and `extensions` information. The legacy schema requires separate API calls to retrieve this information.
- The dictionary is not split into `dictionary_attributes` and `types` but rather presented similar to the metaschema format.

## Other differences
This section cover a laundry list of other differences. Many of these are addressed in the ocsf-server [Bug fixes](https://github.com/ocsf/ocsf-server/pull/169) pull request, created as a way to more easily compare file differences during development of the new compiler.

### Difference 1: broken top-level base_event
The the base event class at legacy output's `base_event` key is not fully processed. This is a longstanding regression bug. Note that the base event class in the legacy schema's `classes` at `classes.base_event` is not fully processed.

### Difference 2: profiles are sorted
The new compiler sorts the various `profiles` string arrays. With the legacy compiler, the order was non-deterministic.

### Difference 3: reverse merging of extension class and object attributes to dictionary
The legacy compiler reverse merged details of extension class and object attributes to the base dictionary. It is unclear why this was done. The new compiler does not do this.

Quirks and bugs I've seen caused by this weirdness:
- The `caption`, `description`, `group`, `profile`, and `requirement` values from classes and/or objects propagated back to dictionary attributes. I did not notice these cases propagated onward to other classes and objects.
- The `group` values propagated from a class or object to the dictionary and then to another class or object.

These should be be non-issues. The cases above do not affect encodings or event validation. However, due to weirdness of this bug, there may well be a private extension out there that propagates a material change.

### Difference 4: profile consolidation in classes and objects
The `profiles` attribute in classes and objects is a consolidation of all its own profiles and all child objects. The legacy compiler implementation did not fully consolidate the profiles of all objects. Interestingly, this did not affect the consolidation of profiles in `classes`.

With the new compiler, `profiles` field in objects includes those of all children. The following objects are affected: `actor`, `affected_package`, `application`, `cis_benchmark_result`, `idp`, `metadata`, `remediation`, `startup_item`, and `vulnerability`.

### Difference 5: dictionary data type extension information
The new compiler adds `extension` and `extension_id` attributes to dictionary data types coming from extensions. This is done for consistency with dictionary attributes.

### Difference 6: type_name set properly for class and object refined types
In dictionary types that are subtypes, `type` refers to the base type's name (e.g., `string_t`), and `type_name` refers to the base type's caption (e.g., "String").

Class and object attributes are allowed to refine the type of their attributes to a subtype or the original. In these cases, legacy compiler was incorrectly populating the attribute details with the dictionary attribute's original base type and caption, rather than the refined type's base type and caption.

### Difference 7: extension scoped names
This is perhaps the biggest difference. The legacy compiler prefixed many names with the extension, a slash, and then the original name, for example `win/win_server`. This prefixing is annoying not consistent.

The new compiler only profile names from extensions, as they appear in concrete events in the `metadata.profiles` field, and so dropping these prefixes would significant backwards incompatibility break.

Here are the general cases that use extension prefixing:
- Class and object names from extensions. These are the keys in the `classes` and `objects` top level fields.
- Class and object attributes whose types are extensions object use extension prefixes in their `object_type` fields.
- Dictionary attribute names from extensions.
- Dictionary attributes attributes whose types are extensions object use extension prefixes in their `object_type` fields.

There is one weird exception to this. I've seen at one case where the legacy compiler has _both_ the extension scoped and unscoped dictionary attribute. This occurs with the `aws` extension with the `aws/last_used_time` and `last_used_time` dictionary attributes. I suspect this a side effect of the reverse merging bug mentioned in Difference 3.

### Difference 8: class and object attribute profile change
There are two differences here.

First, the legacy compiler format sometimes had class and object attribute details with a `profile` with value `null`. There is no equivalent in the new compiler output. This should not cause trouble since OCSF in general does not distinguish between a missing value and `null`.

Second, the new compiler uses `profiles` in class and object attributes. The allows multiple profiles to affect the same attribute. This amounts to design flaw in the legacy compiler output format since it was always possible to define multiple profiles that affect the same attribute.
