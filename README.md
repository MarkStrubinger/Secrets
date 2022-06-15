# Secrets
User Authentication project, using Node, Express, EJS HTML pages, CSS, and JS and using an online MongoDB cluster.

This is a PostSecret-esque website created with the intention to demonstrate proficiency in internet user authentication, 
within a website shell built using the aforementioned tech stack.

Users can register using any email and password, or they can use a Google sign-in service.
The passwords are then hashed and salted using node modules such as passport.
A simple cookie authentication token is also used to recognize a persisted user login session.

After successfully registering or logging in, the user will be taken to the Secrets page where they can input a simple text response, anonymously.
This unique secret is then displayed for other users to see on the Secrets page.
