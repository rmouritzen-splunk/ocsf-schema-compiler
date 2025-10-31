# Baseline compiled schemas
This directory holds compiled schemas used for regression tests, and should be updated as compiler output changes.

Here are example of how these can be created from the command-line. Run these from the base of the repo.
```shell
(cd src && python3 -m ocsf_schema_compiler ../tests/uncompiled-schemas/ocsf-schema-v1.6.0 | jq -S > ../tests/compiled-baselines/schema-v1.6.0.json)

# Using jq with the browser mode variation leads to a file that exceeds GitHub 100MB limit.
(cd src && python3 -m ocsf_schema_compiler ../tests/uncompiled-schemas/ocsf-schema-v1.6.0 -b > ../tests/compiled-baselines/browser-schema-v1.6.0.json)

(cd src && python3 -m ocsf_schema_compiler ../tests/uncompiled-schemas/ocsf-schema-v1.6.0 -e ../tests/uncompiled-schemas/aws-v1.0.0 | jq -S > ../tests/compiled-baselines/browser-schema-v1.6.0-aws-v1.0.0.json)

(cd src && python3 -m ocsf_schema_compiler ../tests/uncompiled-schemas/ocsf-schema-v1.0.0-rc.2 -i -e ../tests/uncompiled-schemas/splunk-v1.16.2 | jq -S > ../tests/compiled-baselines/schema-v1.0.0-rc.2-splunk-v1.16.2.json)
```

The use of `jq -S` is not required but can be helpful when using other diff tools like the one in Visual Studio Code.

Schemas with filenames starting with `server-v3` were created via schema export of the v3 (older) Elixir OCSF Server using the `/export/schema` API.