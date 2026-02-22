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

### Difference 7: hanlding of extension-scoped names
~~This is perhaps the biggest difference. The legacy compiler prefixed many names with the extension, a slash, and then the original name, for example `win/win_server`. This prefixing is annoying not consistent.~~

~~The new compiler uses extension-scoped names with profile names from extensions, as they appear in concrete events in the `metadata.profiles` field, and so dropping these prefixes would significant backwards incompatibility break.~~

This has been largely changed. **TODO** Remove the strike-through paragraphs and this comment after beta period.

**TODO** Describe new handling. Shadowing. Dictionary types.

**NOTE:** class, object, and profile `name` fields are not scoped. (This is unchanged from old compiler to new compiler.)


### Difference 8: class and object attribute profile change
There are two differences here.

First, the legacy compiler format sometimes had class and object attribute details with a `profile` with value `null`. There is no equivalent in the new compiler output. This should not cause trouble since OCSF in general does not distinguish between a missing value and `null`.

Second, the new compiler uses `profiles` in class and object attributes. The allows multiple profiles to affect the same attribute. This amounts to design flaw in the legacy compiler output format since it was always possible to define multiple profiles that affect the same attribute.

## Errors detected by new compiler
The new compiler is stricter than the legacy compiler.

### Error: extensions modifications of dictionary types is not supported
Extensions are not allowed to modify any existing dictionary types. Modifications of dictionary types can easily lead to incompatibilities between events using this extension and events not using it, even for events that otherwise do not use extension additions or changes.

**TODO:** Reconfirm after deciding unscoped vs. scoped dictionary types issue.

### Error: extension patches can only patch the base schema
Extensions can only patches classes and objects in the base schema, including the platform extensions in the base schema.

**TODO:** This is no longer true.


## TODO issues and changes

### This doc
- Describe extension application order. Explain why this is done.
    - Describe old compiler's partial ordering.
- Describe addition of `patched_by_extensions` and `patched_by_extension_ids` attributes to patch items (classes and objects).
- Extensions cannot modify categories in base schema or other extensions.
    - This has always been true.
- Extensions can add dictionary types, but cannot modify them.
    - This is changed. Old compiler allowed extensions to modify dictionary types.
- Removed support for the undocumented "overwrite" property of dictionary attributes.
    - The dictionary attribute "overwrite" property is not supported by the metaschema.
    - I suspect that the "overwrite" property has never been actively used.
    - The old compiler allowed modification of dictionary attributes with this property.
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

#### TODO items for this compiler.

Legacy output should use one higher level of nesting. Top level should have categories, profiles, extensions, and export schema (what output now).

- Define and describe exactly what is allowed during attribute merging.
    - This occurs during patching as well as dictionary attribute to class, object, and profile attribute merging.
    - `SchemaCompiler._merge_attribute_detail`
        - Call tree:
            - `SchemaCompiler._merge_attribute_detail`
                - `SchemaCompiler._merge_attributes`
                    - `SchemaCompiler._merge_attributes_include`
                        - `SchemaCompiler._resolve_item_includes`
                            - `SchemaCompiler._resolve_includes`
                            - `SchemaCompiler._resolve_extension_includes`
                    - `SchemaCompiler._resolve_patches`
                    - `SchemaCompiler._resolve_item_extends`
- Compare `SchemaCompiler._merge_attribute_detail_include` to `SchemaCompiler._merge_attribute_detail`.
    - Note, and possibly raise error, for changes that can cause an incompatibility.
    - Call tree:
        - `SchemaCompiler._merge_attribute_detail_include`
            - `SchemaCompiler._resolve_item_includes`
                - `SchemaCompiler._resolve_includes`
                - `SchemaCompiler._resolve_extension_includes`


### Server issues
**TODO** items for `ocsf-server`. These apply to v3 and v4 unless notes.
- Support for profiles with same name from from different extensions.
    - Profiles checkboxes need to support same profile name from different extensions. Also add extension prefix to name like "Linux/Linux Users".
    - Profile page needs to show extension name.
- v4 : change patch notation handling of `_patched_by_extensions` to `patched_by_extensions` / `patched_by_extension_ids`.
    - These only occur in classes and objects.
- v4 : add notation handling of `extension` and `patched_by_extensions` showing creator and modifier details.
