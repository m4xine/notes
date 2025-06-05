---
title: Git
description: Version control for code files.
---
```shell
git config --global user.name "Mona lisa"
```

```shell
git init
git add .
git commit -m "First commit"
```

```shell
# remove .DS_Store file from GitHub that MAC OS X creates

# find and remove .DS_Store
find . -name .DS_Store -print0 | xargs -0 git rm -f --ignore-unmatch

# create .gitignore file, if needed
touch .gitignore
echo .DS_Store > .gitignore

# push changes to GitHub
git add .gitignore
git commit -m '.DS_Store removed'
git push origin master

```

```shell
# Create a new branch from the top of the main branch.
git checkout -b my-feature-branch main
```

```xml
# Delete Local branch
git branch -d <branchName>
git branch -D <branchName>
```

```shell
# Delete Remote Branch
git push origin --delete <branchName>
```