# Differences between ocsf-server v3 compile and ocsf-schema-compiler
This document covers the differences with the ocsf-server v3 compiler and the ocsf-schema-compiler output. We will refer to the ocsf-server v3 compiler as the "legacy compiler" with its output as the "legacy format", and the ocsf-schema-compiler as the "new compiler" with its output as the "new format".

## Revision history
| Date | Compiler Version | Change |
|-|-|-|
| 2026-02-02 | 0.9.7 | Initial |
| 2026-02-07 | 0.9.8 | Extension scoped names. Errors detected in new compiler. |

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

### Difference 7: extension-scoped names
~~This is perhaps the biggest difference. The legacy compiler prefixed many names with the extension, a slash, and then the original name, for example `win/win_server`. This prefixing is annoying not consistent.~~

~~The new compiler uses extension-scoped names with profile names from extensions, as they appear in concrete events in the `metadata.profiles` field, and so dropping these prefixes would significant backwards incompatibility break.~~

This has been largely changed. The compiler now outputs extension-scoped names for backwards compatibility.

Here are the cases that use extension-scoped name prefixing:
- Class and object names from extensions. These are the keys in the `classes` and `objects` top level fields.
- Class and object attributes whose types are extensions object use extension prefixes in their `object_type` fields.
- Dictionary attribute names from extensions.
    - **NOTE:** extension defined attributes are used _without_extension-scoped names in classes, objects, and profiles.
    - **NOTE:** concrete events use these attributes _without_ extension-scoped attribute names.
    - **NOTE:** the new result is that dictionary attributes _use_ extension-scoped names, but are not, in fact, scoped by extensions.
- Dictionary attributes attributes whose types are extensions object use extension prefixes in their `object_type` fields.

There cases generate different names than the legacy compiler:
- Extension update of base dictionary attribute.
    - The legacy compiler adds this attribute to the dictionary twice: with and without the extension-scoped name, with the update only in the extension-scoped name.
- **TODO:** Extension update of another extension's dictionary attribute.
    - **TODO:** The legacy compiler does what? Same thing.
    - **TODO:** The new compiler does weird things. Adds two extension prefixes. The `extension` and `extension_id` details are from the last updater.
    - **TODO:** this should be an error. Does weird things. Doesn't work in legacy compiler.

I've seen at one case where the legacy compiler has _both_ the extension scoped and unscoped dictionary attribute. This occurs with the `aws` extension with the `aws/last_used_time` and `last_used_time` dictionary attributes.

**TODO:** Extensions update of base categories? Modifying categories in base and other extensions is not possible. Reusing same name as a base category cases masks base category; only the extension's category name can be used.
- This seems to work. Check export.
- Category is extension-scoped in `categories.attributes`.
- In classes, category information is all correct: `category_uid` is properly scoped, `category` is extension-scoped, and `category_name` is from extension.
- Server has UI glitch: needs space between extension in brackets and extension name.
    - Example: "System Activity (Example Extension) [10001]example Category".

### Difference 8: class and object attribute profile change
There are two differences here.

First, the legacy compiler format sometimes had class and object attribute details with a `profile` with value `null`. There is no equivalent in the new compiler output. This should not cause trouble since OCSF in general does not distinguish between a missing value and `null`.

Second, the new compiler uses `profiles` in class and object attributes. The allows multiple profiles to affect the same attribute. This amounts to design flaw in the legacy compiler output format since it was always possible to define multiple profiles that affect the same attribute.

## Errors detected by new compiler
The new compiler is stricter than the legacy compiler.

### Error: extensions modifications of dictionary types is not supported
Extensions are not allowed to modify any existing dictionary types. Modifications of dictionary types can easily lead to incompatibilities between events using this extension and events not using it, even for events that otherwise do not use extension additions or changes.

### Error: extensions patches can only patch the base schema
Extensions can only patches classes and objects in the base schema, including the platform extensions in the base schema.

## TODO issues and changes
- General dictionary attribute question: what sort of changes do we want to allow? There are two cases: extension changes of dictionary attributes, and changes made by classes, objects, and profiles.
- Let's consider extension changes to the dictionary attributes.
    - Currently almost anything is possible.
    - Should this even be allowed?
    - If allowed, what should happen when multiple extensions modify the same dictionary attribute?
        - Caption? Currently last modifier wins.
        - Description? Currently last modifier wins.
        - Type? Currently last modifier wins.
        - Enums? Merged but with overlaps, last modifier wins.
        - Is Array? Currently last modifier wins.
        - Requirement? New compiler uses most relaxed requirement.
    - With the new compiler, extensions are processed in a consistent order.
        - Platform extensions are applied first, in ascending UID order.
        - Non-platform extensions are applied next, in ascending UID order.
    - With the old compiler, extensions are processed in a partially sorted order.
        - The only order possible with with the list of paths supplied by the `SCHEMA_EXTENSION` environment variable.
        - Within each of the `SCHEMA_EXTENSION` elements, there is no ordering.
            - The implementation walks each path element, and the filenames are not sorted.
- Next let's consider class, object, and profile modifications of attributes.
    - Again, almost anything is possible.
    - We could restrict to the following:
        - Change description.
        - Adding enum values.
        - Add requirement.
        - Add group.
        - Add profile.
        - Change type and compatible way (relax type, relax constraint).
    - Other changes would not be allowed, either becoming an warning and ignored, or an error.
        - Caption.
        - Incompatible type change, including `is_array`.
        - Change existing enum values.


### This doc
- Describe extension application order. Explain why this is done.
    - Describe old compiler's partial ordering.
- Describe addition of `modified_by_extensions` and `modified_by_extension_ids` attributes to patch items (classes and objects) and extension modified dictionary types.
- Extensions cannot modify categories in base schema or other extensions.
- Extensions can add dictionary types, but cannot modify them.
    - This is changed. Old compiler allowed extensions to modify dictionary types.
- When extension classes and objects extend from classes or objects in their own extension, the `extends` value includes the extension scope. Example:
    - Extension `extra` defines classes `foo` and `bar`.
    - Class `bar` extends `foo`.
    - New compiler result: the `extends` value in class `bar` will be `extra/foo` (scoped).
    - Old compiler result: the `extends` value in claas `bar` will be `foo` (unscoped).
    - Note that retaining the old behavior flattens the namespace of classes and objects, essentially making these names unscoped.
- When an extension modifies a base schema dictionary attribute, the old compiler would retain the original dictionary attribute and add the extension's attribute with a scope. Example:
    - Extension `extra` modifies dictionary attribute `comment`.
    - New compiler result: dictionary attribute `comment` is modified. The modified attribute is consistently used everywhere.
    - Old compiler result: dictionary attribute `comment` is unmodified and dictionary attribute `extra/comment` is added.
        - There are now two versions of this attribute.
        - The schema browser shows only the original attribute, and only mention references from the base schema to the original attribute.
        - Extension items (classes, objects, and profiles) that use the modified dictionary attribute contain details the modified attribute. Note that the attribute name is unscoped in this case, so its details will not match those for the unscoped name in the data dictionary.
        - This behavior is similar to how classes, objects, and profiles can modify dictionary attributes when used in a specific case; typically to change the description as well as add enum values.
        - However, this behavior breaks OCSF's contract of a single consistent data dictionary, allowing each extension to have its own variation of a dictionary attribute, shared among all items in the extension. This makes a certain amount of sense, however it might be unexpected.


### Compiler issues and changes
**TODO** items for this compiler.
- DONE - Multiple extensions updating the same dictionary attribute.
- Multiple extensions patching the same class or object. (These may not be quite right.)
    - Platform extensions can patch same item.
    - Exactly one non-platform extension can patch and already patched item, even one patched by platform.- Non-platform extensions cannot patch a patched done by another. (Needed?)
- Check for extension object name that shadows base object name.
    - Error?
- Check for extension dictionary attribute name that shadows base dictionary attribute name.
    - Error?
- Check for extension category name that shadows base extension name.
    - Error?


### Server issues
**TODO** items for `ocsf-server`. These apply to v3 and v4 unless notes.
- Support for profiles with same name from from different extensions.
    - Profiles checkboxes need to support same profile name from different extensions. Also add extension prefix to name like "Linux/Linux Users".
    - Profile page needs to show extension name.
- v4 : change patch notation handling of `_patched_by_extensions` to `modified_by_extensions`.
- v4 : add notation handling of `extension` and `modified_by_extensions` showing creator and modifier details.
