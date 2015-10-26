#Flask-Now
**Create a Bootstrap-enabled Flask app quickly with this starter kit.**

The app
code and template code is currently based on examples from the book
"Flask Web Development" by Miguel Grinberg.


##Prerequisites
- Linux OS (might work on Windows with some minor tweaking)
- python
- python-dev
- git
- pip
- virtualenv


##Prequisite Installation Instructions (Ubuntu)
**Update package lists**
```
sudo apt-get update
```

**Install python**

*It is very likely that python is already installed.*
```
sudo apt-get install python
```

**Install pip**
```
sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe"
sudo apt-get update
sudo apt-get install python-pip
```

**Install virtualenv**
```
sudo pip install virtualenv
```

**Install python-dev**
```
sudo apt-get install python-dev
```

**Install and configure git**
```
sudo apt-get install git
git config --global user.name "Your Name Here"
git config --global user.email "your_github_username@users.noreply.github.com"
```


##Prequisite Installation Instructions (Debian)
**Update package lists**
```
sudo apt-get update
```

**Install python**

*It is very likely that python is already installed.*
```
sudo apt-get install python
```

**Install pip**
```
sudo apt-get install python-pip
```

**Install virtualenv**
```
sudo pip install virtualenv
```

**Install python-dev**
```
sudo apt-get install python-dev
```

**Install and configure git**
```
sudo apt-get install git
git config --global user.name "Your Name Here"
git config --global user.email "your_github_username@users.noreply.github.com"
```


##Prequisite Installation Instructions (other Linux distros / Windows)
To be added at a later time...


##Create Your App
The ```create``` script initializes a virtual environment using virtualenv,
acquires all prerequisite packages that the app needs to run properly, and
then initializes a fresh git repository for your new app. When the script
completes, your shell will be left in the virtual environment so you can
run the app. To learn more about this virtual environment, Google "virtualenv".
```
git clone https://github.com/richgieg/flask-now.git your-app-name-here
cd your-app-name-here
source create
```


##Run
Your shiny new app comes with the Flask-Script extension, which allows a
finer level of control over your app's execution from the command line. Also
included, thanks to Miguel Grinberg, is a ```manage.py``` script which makes
use of Flask-Script to provide some necessary commands. The
following command executes your app on the development server with debugging
and auto-restarts enabled.
```
./manage.py runserver
```


##Connect
Now that your app is running on the development server, you can access it
from your browser by visiting the following address:
```
http://localhost:5000
```


##Stop
*Press CTRL+C in your terminal to stop development server.*
```
```


##Deactivate the Virtual Environment
When you're done developing and testing your app, you can return your shell
back to its original state by deactivating the virtual environment.
```
deactivate
```


##Reactivate the Virtual Environment
In order to run the app again after deactivating the virtual environment, you
will need to reactivate it.
```
source activate
```


##Install Packages
If your app requires more functionality, you can run the ```add``` command to 
install extra packages, as long as your virtual environment is active. This
command is just a wrapper for the ```pip install``` command which adds the
dependency to your app's ```requirements.txt``` file so when others
clone your repository they will be able to easily acquire all of the necessary
packages to execute it (see "How Others Can Run Your App" below).
```
add flask-babel
```
*```flask-babel``` can be replaced with any other pip-installable package.*

##Share Your App
As soon as you've run the steps in the "Initialize" section above, you'll have a clean,
fully-functioning local git repository for your new app that you can share on GitHub.
To do so, create a new repository in your GitHub account, then link your local
repository to the GitHub repository.
```
git remote add origin https://github.com/your-user-name/your-repo-name.git
git push -u origin master
```

##How Others Can Run Your App
When other developers clone your repository, they will need to create and initialize a
virtual environment on their own local system and acquire your app's prerequisites. This
is accomplished by running the ```setup``` script below.
```
git clone https://github.com/your-user-name/your-repo-name.git
cd your-repo-name
source setup
./manage.py runserver
```
