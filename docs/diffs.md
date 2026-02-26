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
    "categories": {
        "caption": "Categories",
        "description": "...",
        "name": "category",
        "attributes": {
            // Base schema categories
            "<category_name>": {
                "caption": "<short name>",
                "description": "<description>",
                "uid": 1
            },
            // Categories from extensions always use extension-scoped name
            "<ext_name>/<category_name>": {
                "caption": "<short name>",
                "description": "<description>",
                "extension": "<ext_name>",
                "extension_id": 1, // extension uid
                "uid": 199 // 100 * extension uid + category uid in extension
            }
        }
    },
    "dictionary": {
        "caption": "Attribute Dictionary",
        "description": "...",
        "name": "dictionary",
        "attributes": {
            // Base schema dictionary attributes
            "<attribute_name>": {
                // attribute properties
            },
            // Dictionary attributes from extensions always use extension-scoped name
            "<ext_name>/<attribute_name>": {
                // attribute properties
                "extension": "<ext_name>",
                "extension_id": 1, // extension uid
            }
        },
        "types": {
            "caption": "Data Types",
            "description": "...",
            "attributes": {
                // Base schema dictionary types
                "<type_name>": {
                    // type properties
                },
                // Platform extensions dictionary types
                // and dictionary types from non-platform extensions
                // if compiled with --unscoped-dictionary-types enabled (True)
                "<attribute_name>": {
                    // type properties
                    "extension": "<ext_name>",
                    "extension_id": 1, // extension uid
                },
                // Dictionary types from non-platform extensions
                //      if compiled with --unscoped-dictionary-types enabled (True)
                "<ext_name>/<attribute_name>": {
                    // type properties
                    "extension": "<ext_name>",
                    "extension_id": 1, // extension uid
                }
            }
        }
    },
    "classes": {
        // class name is extension scoped when from an extension: "<ext_name>/<class_name>"
        "<class_name>": {
            "caption": "<short name>",
            "category": "<category_name>",
            "category_name": "<category_caption>",
            "category_uid": 3,
            "extension": "<extension_name>", // if class is from extension
            "extension_id": 1, // if class is from extension
            "description": "...",
            "extends": "<base_class_name>", // if applicable
            "name": "account_change", // name property is never extension-scoped
            "profiles": [
                "<profile_name>",
                "<ext_name>/<profile_name>", // pextension-scoped when from extension
            ],
            // class uid = 1000 * category uid + class uid
            // For extension the category-scoped is used, effectively
            //      class uid = 1000 * ((100 * extension uid) + category uid) + class uid
            // NOTE: The extension variation causes a potential class uid collision
            //       with classes in the same extension using a mix of base and extension
            //       categories with the same base category uid, while using the same class
            //       uid (which are meant to be scoped by category). See below.
            "uid": 3001,
            // other class properties
            "attributes": {
                // attribute names are never extension-scoped
                "<attribute_name>": {
                    // attribute properties
                }
            }
        }
    },
    "objects": {
        // object name is extension scoped when from an extension: "<ext_name>/<object_name>"
        "<object_name>": {
            "caption": "<short name>",
            "description": "...",
            // other object properties
            "attributes": {
                // attribute names are never extension-scoped
                "<attribute_name>": {
                    // attribute properties
                }
            }
        }
    },
    "profiles": {
        // profile name is extension scoped when from an extension: "<ext_name>/<profile_name>"
        "<profile_name>": {
            // profiles properties - does not include attributes
        }
    },
    "extensions": {
        "<ext_name>": {
            "caption": "<short name>",
            "description": "...",
            "name": "<ext_name>",
            "platform_extension?": false, // or true
            "uid": 100,
            "version": "<major>.<minor>.<patch>"
        }
    },
    "version": "<major>.<minor>.<patch>",
    "compile_version": 1, // currently always 1
}
```

For reference, the legacy `/export/schema` API returns the following top-level structure:
```json5
{
  "base_event": {}, // note: this is broken in current version 3.1.0 (it is not fully processed)
  "classes": {},  // includes "base_event" (this version of base_event is not broken in v3.1.0)
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

The `/api/categories`, `/api/extensions`, and `/api/profiles` APIs are needed to get the remaining details of the schema.

## Potential extension class uid collision
Class UIDs are meant to be scoped by category. All UIDs in an extension are meant to be scoped by the extension. However there is one situation where this breaks down due to the math used to create the extension-scoped UIDs.

The colliding situation is the following:
1. An extension has a category with a UID that is the same a base schema category. Normally extension categories using the same UID as a base category is fine.
2. The extension has two classes, one of which uses the base schema category above and the other uses the extension category. Both of these classes use the same UID. Normally classes that use the same UID is fine so long as use different categories.

The problem that formula creating an extension-scoped category UID overlaps with the formula for creating an extension-scoped class UID.

These are the formulas.
- Extension-scoped category UID: (100 * category UID)
- Category-scoped class UID:
    - For base schema classes:
        - (1000 * category UID) + class UID
    - For extension classes that use base schema categories:
        - (1000 * ((100 * extension UID) + base category UID)) + class UID
    - For extension classes that use extension categories:
        - (1000 * ((100 * extension UID) + unscoped category UID)) + class UID

The flaw is that for extension classes, both base category UIDs and extension category UIDs are both treated as if they come from the extension.

The old compiler does not detect this situation and generates extension classes with the same UID values. The new compiler issues a warning when extension category UIDs match a base category UID, as well as an error for class UID collisions. Indeed, the new compiler checks for collisions with all UIDs: extension UIDs, categories (after extension-scoping), and class UIDs (after extension-scoping).

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

### Difference 7: handling of extension-scoped names
~~This is perhaps the biggest difference. The legacy compiler prefixed many names with the extension, a slash, and then the original name, for example `win/win_server`. This prefixing is annoying not consistent.~~

~~The new compiler uses extension-scoped names with profile names from extensions, as they appear in concrete events in the `metadata.profiles` field, and so dropping these prefixes would significant backwards incompatibility break.~~

This has been largely changed. As of v0.9.8, the new compiler now uses extension-scoped names the same way as the old compiler with two differences: extension defined dictionary types and other extension names that collide with base schema names.

First, dictionary types are handled different. The old compiler uses unscoped names for dictionary data types defined in extensions. This opens up the possibility new collisions should a future base schema version also add a dictionary data type with the same name. By default, the new compiler uses extension-scoped names for dictionary types defined in extensions other than platform extensions. The dictionary types added in platform extensions remain unscoped for backwards compatibility.

This behavior can be changed with the `-u, --unscoped-dictionary-types` option. Developers of existing extensions that define dictionary types will want to use this option to avoid a breaking change when using the new compiler.

Second, extension items with names that collide with base schema names cause an error by default, since this causes uses in the extension to _shadow_ the same item in the base schema, preventing the extension from using the base schema version of this item. (Remember that extensions refer to both base schema names and their own item names without a scope.) This behavior can be changed with the `-a, --allow-shadowing` option. When shadowed names are enabled, the new compiler will still issue a warning since additions to existing schema should still avoid these name collisions.

### Difference 8: class and object attribute profile change
There are two differences here.

First, the legacy compiler format sometimes had class and object attribute details with a `profile` with value `null`. There is no equivalent in the new compiler output. This should not cause trouble since OCSF in general does not distinguish between a missing value and `null`.

Second, the new compiler uses `profiles` in class and object attributes. The allows multiple profiles to affect the same attribute. This amounts to design flaw in the legacy compiler output format since it was always possible to define multiple profiles that affect the same attribute.

### Difference 9: extension are processed deterministically
The new compiler processes extensions in a deterministic manner. This is useful in cases where extensions extend or patch items in other extensions.

Processing order:
1. Platform extensions — those in the base schema's `extensions` directory — are processed first, in ascending extension UID order.
2. Other extensions are processed in ascending extension UID order.

By contract, the old compiler processed extension in a partial order. Each paths in the `SCHEMA_EXTENSION` environment variable was considered in order, however the extensions inside each path were not processed in any sort order.

### Difference 10: undocumented dictionary attribute overwrite flag
The new compiler removes support for the undocumented `overwrite` property of dictionary attributes.

Note that the dictionary attribute `overwrite` property has never been supported by the metaschema. I suspect that the "overwrite" property has never been actively used.

The old compiler allowed modification of dictionary attributes with this property. However, this creates the possibility of incompatible schemas.

## Difference 11: extension names that shadow base schema names
Extension names that that can shadow base schema names are an error by default.

Shadowing can occur with the following kinds of extension defined items:
- Category names
- Class names
- Object names
- Dictionary attribute names
- Dictionary type names
    - This applies to non-platform (_private_) extension when the `-u`, `--unscoped-dictionary-types` option is _not_ enabled (the default). Dictionary type names that collide with the base schema are always an error for platform extensions, and are an error for non-platform (_private_) extensions when the `-u`, `--unscoped-dictionary-types` is enabled.
- Profile names

With the definition of an extension all names are unscoped. There is no way to distinguish between the base schema version of a name and an extension version of with the same name. When shadowing is enabled, the extension can _only_ use their version of the named item.

This behavior can be changed with the `-a`, `--allow-shadowing` compiler option. This option is only recommended for existing extensions to maintain backwards compatibility. When enabled, shadowed names become a warning. These warnings should be examined since newly defined names should avoid colliding with base schema names to allow current or future uses of the base schema name.

**TODO:** Should class names be checked for shadowing? These don't seem to be used anywhere. This check will be left for now pending feedback from the community.

## Difference 12: extension profiles without extension-scope
Most extension-defined items are referenced without an extension-scope, however when profile names are referenced in the extension class and object top-level `profiles` attribute, they are typically referenced _with_ an extension-scope.

When an extension-define profile is referenced _without_ a scope, things get messy. The old compiler simply keeps the unscoped profile name, causing a mismatch between the profile's name in attributes that are enabled by the profile, and the name of the profile in the top-level class or object `profiles` property.

When the new compiler encounters an unscoped profile name that is defined in the extension, it adds the extension-scope to the name. This fix-up avoids the name mismatch caused by the old compiler.

### Include files and extension-scoped profiles
Profile are also typically implemented using the magic `$include` attribute name in class and object definition with a value that is a relative path. For extensions, the include file handling always looks for this file _first_ relative to the extension's base directory (where the `extension.json` file is at), and next in the base schema directory. (Both the old and new compilers share this behavior.)

The old compiler's extension-define profile name mismatch above is further compounded by always pulling in the extension-define include file. In other words, if an extension tried to define a shadowed, extension-specific version of a profile with the same name as a base class, but one in one case wanted an extension class or object to use the base schema profile, it wouldn't work. Although class or object would have the base schema's profile name in its top-level `profiles` attribute, the details included with the `$include` directive would pull in the extension-specific attributes.

In short, the old compiler's approach is broken in this case. The new compiler tries to do something sensible, allowing unscoped extension-define profile name references to work like every other extension item name reference: unscoped.

## Errors detected by new compiler
The new compiler is stricter than the legacy compiler. Below are the more notable errors.

### ~~Error: extensions modifications of dictionary types is not supported~~
~~Extensions are not allowed to modify any existing dictionary types. Modifications of dictionary types can easily lead to incompatibilities between events using this extension and events not using it, even for events that otherwise do not use extension additions or changes.~~

This is changed with ocsf-schema-compiler v0.9.8. See next section.

### Error: extension dictionary type name collision with base schema dictionary type
Dictionary types defined in extensions other than platform extension are now extension-scoped by default. Dictionary types defined in platform extension remain unscoped for backwards compatibility. When the unscoped dictionary types option is enabled, name collisions with the base dictionary types is an error.

If you are maintaining an extension, and this error occurs when compiling with a new version of the base schema, this means your extension is no longer compatible with the base schema from that version and forward. Your only options are to use a different dictionary type name in your extensions (a backwards incompatible change that _might_ be tolerable in your organization's specific usage), or create your own incompatible fork of the base schema. In other words, you're stuck and there is no good path forward.

This is new behavior with v0.9.8. The old compiler allowed modifying base schema dictionary types, silently allowing the possibility to create a schema incompatible with a schema compiled without your extension.

### ~~Error: extension patches can only patch the base schema~~
~~Extensions can only patches classes and objects in the base schema, including the platform extensions in the base schema.~~

This is changed with ocsf-schema-compiler v0.9.8. Extensions can patch items patched by other extensions.

### Error: unique ID collision
The new compiler checks for unique ID collisions in categories, classes, and extensions.
