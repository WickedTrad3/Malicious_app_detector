## set email to your account
**git config --global user.email "email"**

## set name to your account
**git config --global user.name "name"**


## adds files for commit 
**git add .**
## saves the changes made to a save
**git commit -m "name of commit"**

## add commits to remote repository
**git push -u \<remote name\> \<branch name\>**

## grab latest version from remote repository and merge with current local repo
**git pull <remote name>**

## create new branch 
## create when working on a section
**git branch <name>**

## go to branch for pulling and pushing
**git checkout <branch>**

## remove cache in case of adding of file that shouldnt be commited
**git rm -r --cached <name of folder/file>**

## see status of modified
**git status**

## used to build docker image off docker file located in repo
**docker build -t <image name> .**

## create container from image
**docker container create -i -t --name <container> <>**
** docker container create -i -t --name <container> <> **

# see status of modified
git status 

# used to build docker image off docker file located in repo
docker build -t <image name> .

# create container from image
docker container create -i -t --name <container> <>

# how to run jadx
go to jadx dir, run jadx -d (location of dir to place it in)