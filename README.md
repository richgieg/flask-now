#Flask-Now
**Create a Bootstrap-enabled Flask app quickly with this starter kit.**

The app
code and template code is currently based on examples from the book
"Flask Web Development" by Miguel Grinberg. This may change as the project
matures.


##Requirements
- Linux
- git
- python-dev
- virtualenv


##Initialize
The ```create``` script initializes a virtual environment using virtualenv,
acquires all prerequisite packages that the app needs to run properly, and
then initializes a fresh git repository for your new app.
```
git clone https://github.com/richgieg/flask-now.git [your-directory-here]
cd [your-directory-here]
source create
```


##Run
Your shiny new app comes with the flask-script extension, which allows a
finer level of control over your app's execution from the command line. The
following command executes your app on the development server with debugging
and auto-restarts enabled.
```
python app.py runserver -d -r
```


##Stop
*Press CTRL+C to stop development server.*


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

##Share Your App
As soon as you've run the steps in the "Initialize" section above, you'll have a clean,
fully-functioning local git repository for your new app that you can share on GitHub.
To do so, create a new repository in your GitHub account, then link your local
repository to the GitHub repository.
```
git remote add origin https://github.com/[your-user-name]/[your-repo-name].git
git push -u origin master
```

##How Others Can Run Your App
When other developers clone your repository, they will need to create and initialize a
virtual environment on their own local system and acquire your app's prerequisites. This
is accomplished by running the ```setup``` script below.
```
git clone https://github.com/[your-user-name]/[your-repo-name].git
cd [your-repo-name]
source setup
python app.py runserver -d -r
```
