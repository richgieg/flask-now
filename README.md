#Flask-Now
**Use this starter kit to quickly create Bootstrap-enabled Flask web applications
with built-in user management and email functionality.**

I became inspired to start this project as I was working through the book [Flask Web Development](http://flaskbook.com/) by [Miguel Grinberg](http://blog.miguelgrinberg.com/). I wanted to have a template I could utilize to quickly build new web applications, without having to worry (or at least not as much) about the details of user management and security. Starting with code from the book's corresponding
Flask application called [Flasky](http://github.com/miguelgrinberg/flasky), this project was born. If you want to learn about Flask, I highly recommend Miguel's book. If you enjoy working with Flask and you want a codebase to spin up a user-based web application quickly, I hope this project is useful to you. A huge thanks goes out to the Flask community and all the Flask extensions utilized in this project!

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


##Set Environment Variables
Flask and many of its extensions utilize a value called SECRET_KEY in order to
perform digital signing. There is a default value for this in ```config.py```
but it's wise to set it to a top-secret value stored in an environment variable
(especially when in production). Also, you should set the APP_ADMIN variable,
which corresponds to the email address of the app administrator. This
serves to automatically assign admin rights when you initially create the admin
user account through the app's user registration page. To save some trouble
on the next time you want to run the app, it is recommended to write
a script to set the environment variables. Just be sure not to share the script
though, as some of the environment variables contain sensitive information.
```
export SECRET_KEY=this_should_be_a_long_and_random_value
export APP_ADMIN=admin@example.com
```


##Configure Email Functionality
For the app to be able to send emails, you will need to set more environment
variables and adjust settings in ```config.py```.

```
export MAIL_USERNAME=user@example.com
export MAIL_PASSWORD=My$trongPa$$w0rd
```
*In ```config.py``` look for constants beginning with MAIL_ and make necessary
adjustments to enable email functionality through your mail server of choice.
The app is configured to use Google's Gmail server by default.*


##Initialize the SQLite Database
Your shiny new app comes with the Flask-Script extension, which allows a
finer level of control over your app's execution from the command line. Also
included, thanks to Miguel Grinberg, is a ```manage.py``` script which makes
use of Flask-Script to provide some helpful commands. Before running your app,
you will need to initialize its database. This can be completed by executing
the following commands.
```
./manage.py db upgrade
./manage.py insert
```


##Run
The
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
./manage.py db upgrade
./manage.py insert
```
Also, they may need to alter the email server settings in ```config.py``` as
well as set the required environment variables (see "Set Environment Variables"
and "Configure Email Functionality" above). After that, they can execute your
app.
```
./manage.py runserver
```
