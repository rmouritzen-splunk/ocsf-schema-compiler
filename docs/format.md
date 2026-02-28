# Shared structures
## Common "item" structure
```json5
{
  "name": "<name>", // internal name using snake_case
  "caption": "<caption>", // human readable caption; short name
  "description": "<description>", // human readable full description
}
```

## Event class structure
Event classes extend item structure
```json5
{
  "name": "<class_name>", // class name using snake_case
  "caption": "<caption>", // human readable caption
  "description": "<description>", // human readable full description
  // class specific fields
  "category": "<internal_category_name",
  "category_uid": 0, // category unique identifier
  "profiles": ["..."], // list of profiles that apply to this class
  "uid": 0, // class unique identifier; events refer to this as "class_uid"
  "attributes" : {
    "<attribute_name>": {
      "caption": "<caption>"
    },
  }
}
```

