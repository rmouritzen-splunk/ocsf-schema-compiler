# Baseline compiled schemas
This directory holds compiled schemas used for regression tests, and should be updated as compiler output changes.

The compiled schemas are compressed with zstd (available on Mac with Homebrew) to get well below GitHub's LFS warning, especially with the browser schema variations.
```shell
brew install zstd
```

Here are example of how these can be created from the command-line. Run these from the base of this repo.
```shell
python3 -m venv .venv
source ./.venv/bin/activate
pip install -e .

ocsf-schema-compiler tests/uncompiled-schemas/ocsf-schema-v1.6.0 | zstd > tests/compiled-baselines/schema-v1.6.0.json.zst

ocsf-schema-compiler tests/uncompiled-schemas/ocsf-schema-v1.6.0 -b | zstd > tests/compiled-baselines/browser-schema-v1.6.0.json.zst

ocsf-schema-compiler tests/uncompiled-schemas/ocsf-schema-v1.6.0 -e tests/uncompiled-schemas/aws-v1.0.0 | zstd > tests/compiled-baselines/schema-v1.6.0-aws-v1.0.0.json.zst

ocsf-schema-compiler tests/uncompiled-schemas/ocsf-schema-v1.0.0-rc.2 -i | zstd > tests/compiled-baselines/schema-v1.0.0-rc.2.json.zst

ocsf-schema-compiler tests/uncompiled-schemas/ocsf-schema-v1.0.0-rc.2 -i -e tests/uncompiled-schemas/splunk-v1.16.2 | zstd > tests/compiled-baselines/schema-v1.0.0-rc.2-splunk-v1.16.2.json.zst

ocsf-schema-compiler tests/uncompiled-schemas/ocsf-schema-v1.6.0 -e tests/uncompiled-schemas/example-extension | zstd > tests/compiled-baselines/schema-v1.6.0-example-v1.0.0.json.zst
```

Schemas with filenames starting with `server-v3` were created via schema export of the v3 (older) Elixir OCSF Server using the `/export/schema` API.

```shell
# Clone the v1.6.0 ocsf-schema, the v1.0.0 aws extension, and the v3 ocsf-server
# Run v3 ocsf-server with the following environment:
export SCHEMA_DIR=$HOME/github/ocsf/ocsf-schema-v1.6.0
export SCHEMA_EXTENSION=$HOME/github/ocsf/ocsf-schema-v1.6.0/extensions,$HOME/github/ocsf/aws-v1.0.0
iex -S mix phx.server

# In another shell, run this from the base of this repo:
curl http://localhost:8080/export/schema | zstd > tests/compiled-baselines/server-v3-schema-v1.6.0-aws-v1.0.0.json.zst
```
