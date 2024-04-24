docker build -t image_detector .
# adds files for commit 
git add .
# saves the changes made to a save
git commit -m "name of commit"

# add commits to remote repository
git push -u <remote name> <branch name>

# grab latest version from remote repository and merge with current local repo
git pull <branch> 

# create new branch 
# create when working on a section
git branch <name>

# go to branch for pulling and pushing
git checkout <branch>

# remove cache in case of adding of file that shouldnt be commited
git rm -r --cached <name of folder/file>

# see status of modified
git status