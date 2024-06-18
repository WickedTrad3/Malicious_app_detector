# Guide to GitHub

There are 2 ways to commit to github, using github website directly to add and edit files, or using Visual Studio Code to commit and push to github

commits are meant to be used to create histories and "snapshots of files". This allows for reverting to previous versions as well as downloading other versions.

# guide to GitHub

go to the correct branch and edit files directly. This is only reccomended if you are lazy and want to change minor details, since a commit is still necessary.

# guide to Visual Studio Method

## setting up git in VS code

This is a good link to understand how to use git in visual studio code

https://code.visualstudio.com/docs/sourcecontrol/intro-to-git

Download git from this link and install using default parameters

https://git-scm.com/downloads

![alt text](<guide images/Screen-Shot-2020-03-11-at-8.47.50-am.webp>)

Ensure that git is enabled as shown above

``` 
console git config --global user.name "yourusername"
git config --global user.email "email@youremail.com"
```

follow these commands to set the username and email of the user in git in VScode

```
git config --global --list
```

## adding remote repository

![alt text](<guide images/addremote.png>)

click on add remote, then add the url from the repository

## cloning repository

click on clone repository(?)

## commiting code to a tag and pushing to remote repository

tag is the name of the version that you have saved. To commit to local repository, go to source control (ctrl-shift-g), add in your tag name under message, and click on commit all. Accept staging all files in order to commit all files.

press on push in order to save the latest commit to the remote repository. **Please** ensure that there are no conflicts with latest version that you are currently working on.

![alt text](<guide images/scm-more-actions.png>)

![alt text](<guide images/commit.png>)

![alt text](<guide images/commitall.png>)

When saving a version of the code to git, make sure to add a message to identify the version

![alt text](<guide images/main.png>)

Then check the branch that you are currently on. This can be seen at the bottom of the left hand side. Click on it to see the different branches.

checkout to the correct branch, and clone the repository to initialize your own local repository. Make sure to add your own branch, or change to the branch that you want to add to.

## merging branches

to merge your branch with main, checkout to main (branch that is recieving the merge) and merge with the needed branch