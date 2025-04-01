# CyberTalk
#### Video Demo: [Youtube link](https://youtu.be/X2sQn0x4B78). (https://youtu.be/X2sQn0x4B78)
## Description:
This is a dynamic web based aplication, designed to facciliate real-time messages via JSON. With features like user authentication, users can log in securely and personalize their experience with unique usernames and emojis. The application supports a visually appealing chat interface that updates in real-time

## Installing Librarys
Firstly run this command:
`pip install flask`

And this one:
`pip install flask_login`


And if not installed:
`pip install cs50`

Also run
`pip install flask_session`

Or install them in one go:
`pip install flask flask_login cs50 flask_session
`
## What each library does
* Flask is a lightweight web framework that developers to build web applications quickly and easily.
* Flask_login is an extention for flask that provides user sessions to work. Similar to _helpers.py_ in **pset 9**
* CS50's library is for using SQL in python.


## Register/Log in.
Firstly you need to run `flask run` to create the web application. Then go to the _url_.

On the screen there are two buttons, ***Get Started*** and ***Log In***. Click log in if you haven't created an account, then click _Get started_.

On the ***Get started*** screen you need to input a username and password and then confirm you password by re-entering the same password. Then chose an emoji. from the following then hit register. You will then immediately be logged in.

On the ***Log In*** screen you will see an input that will tell you to log in with the account you created in the _Get started_ process. If you have not created an account, then press the button on the top that says ***Register***

## Once logged in

### Home screen and bar:
The home screen is the screen that is there when you are logged on. The header bar on top has your navigations, such as, ***Generate***, ***Join group***, ***Dark mode*** and ***Log out***. On the bottom there is a delete account button, if you want to delete your account.
* The 'Generate' is to generate a group id and inputing it to a SQL database (Week 7)
* The 'Join group' is to join a group with a group id. It uses SQL to find if it is in the database
* Dark mode is just triggering a CSS file (Week 8)
* 'Log out' just clears you session data.

### Generate
Click the _Generate_ on the top of the header, when you click it it will change to ```/generate```. Then you can see the 'Generate key' button. If you click that it gives you a unique key. for example mine gave ```Your unique key is: #######```. It can generate a random integer from 1,000 to 10,000,000. Copy that key and go to the next step.
### Join group
The 'Join group' is on the top in the header. Click it. the url will change to ```/chat```. Input the key from before into the input box then press _Join Chat_. If you input a wrong key, it will say ```Invalid key. Please try again.``` If you enter the correct key then you will be redirected to the chat room.
### The Chat Room
The chat room has the same url as the Join Group ```/chat```. But this time you can chat. Input your message into the text box that says ```Type your message```. Once you have typed your message into the text box press ```Send```, or press **Enter**. You will see it pop up in the chat window in a blue bubble. If someone else is in the chat then they will see your message in a grey bubble. The message is being sent using JSON and uses fetch to search for new a message. You can also delete the chat by pressing the delete chat button on the top.
The format for the JSON is this:
~~~
{"3881912": [{"username": "h", "emoji": "\ud83d\ude00", "message": "hi", "timestamp": "2024-09-25T17:47:23.057119"}]}
~~~
### Other
* You can log out by pressing the 'Log out' button on the top, this will log you out of the web application.

* You can toggle _Dark mode_ by pressing the button on top

* You can see your Username on the top as well as your emoji
### Errors
* If you try to do something that you were not meant to. Like not putting anything it will tell you that you need to fill in all fields. And if the passwords dont match then it will tell you so. When you log in and the username or password is invalid it will say so, this will prevent any glitches in the system



