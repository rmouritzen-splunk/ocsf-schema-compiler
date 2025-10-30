# Uncompiled schemas
This directory holds copies of uncompiled schemas and schema extensions. These are created using git clone and then extraneous information is removed such as the `.git` directory and `.gitignore`. 

These can be add as follows. From this repo's `tests/uncompiled-schemas` directory, run these commands:
```shell
branch=v1.6.0                                                                                                       git 
git clone --single-branch --branch $branch https://github.com/ocsf/ocsf-schema.git ocsf-schema-$branch
cd ocsf-schema-$branch
rm -rf .git .gitignore .github .vscode templates ocsf.png CHANGELOG.md CONTRIBUTING.md

# I also like changing the base README.md as well.
echo "This is a stripped down git clone of the OCSF Schema ${branch} branch." > README.md
```

Public extension are copied similarly.

AWS Extension:
```shell
branch=v1.0.0
git clone --single-branch --branch $branch https://github.com/ocsf/aws.git aws-$branch
cd aws-$branch
rm -rf .git .gitignore CHANGELOG.md
echo "This is a stripped down git clone of the AWS Extension ${branch} branch." > README.md
```

The splunk does not (yet) use branches. You'll have to look at the current `extension.json` file on GitHub to get the version (https://github.com/ocsf/splunk).
Splunk Extension:
```shell
branch=v1.16.2
git clone --single-branch https://github.com/ocsf/splunk.git splunk-${branch}
cd splunk-$branch
rm -rf .git .gitignore .github
echo "This is a stripped down git clone of the Splunk Extension at version ${branch}." > README.md
```
