# Setup Development Environment

This document provides details for developers working on `{$project_name}`. 

## Dev tools

* VSCode
  * change-case
  * Code Spell Checker
  * Python (from Microsoft)
  * Pylance
  * Bracket Pair Colorizer
  * MongoDB for VSCode
  * Docker
* Docker
* git
* Postman

##  Start the API

in `src` folder

```bash
./image-build 1.0.0
docker compose up -d
```

Test with

```bash
curl localhost:2112
```

## Populate the database

in `src/populate folder`

```bash
./full_pop
```

Test with

```bash
curl localhost:2112
```

## Run/Debug API in VSCode

Make sure the API isn't running in docker (leave the mongo container running)

```bash
docker stop {$project_name}
```

* Open Folder in VSCode

  * `src/{$project_name}`

* Create `_env.conf` file (optional)

  * There are a number of settings to configure the API at deploy time

  * These are generally set using the OS environment variables (specified in docker-compose.yml serverless.yml, etc)

  * To set these settings in your dev environment, use this file - this saves having to create enviornment variables on your machine, and saves making changes to the code.

  * Settings in the `_env.conf` file override actual envars.  

  * This file is listed in `.gitignore` so will not be included when you commit/push

  * Recommended settings:

    ```bash
    ES_TRACE_LOGGING=Disabled
    ES_LOG_TO_FOLDER=Disabled
    ES-AUTH_ADD_BASIC=Yes
    ES-AUTH_ENABLE_ROOT_USER=Yes
    ```

* Open `run.py`

* F5 to run with debugging (or ^F5 to run without debugging)

  * If prompted to select a debug configuration, choose "**Python File** Debug the current active Python file" (i.e. `run.py`)

## Run Tests

* Click the Testing icon (the beaker)
* Click Configure Python Tests
* Select pytest
* Select the tests folder
* Ensure MongoDB is running
* Click Run Tests (the double play button) or Debug Tests (play button with a bug)

## Connect MongoDB

* `localhost`
  * Click the MongoDB icon (the leaf)
  * Click Add Connection
  * Click Advanced Connection Settings - take the defaults
* Dev instance (MongoDB Atlas)
  * Click the MongoDB icon
  * Click Add Connection
  * Click Connect with Connection String

With a connection active:

* Click Create New Playground

* delete sample code


## Refresh docker image after changing code

If you are running the API in docker and you make a code change, you must rebuild the docker image.

Given we are not pushing images to a repo, the following is a quick and dirty way to do this:

in the `src` folder:

```bash
docker stop {$project_name}
./wipe_all_images
./image-build 1.0.0
docker compose up -d
```

## Setup Postman

Create two environments

* In one set `url` variable to `localhost:2112`
* In the other set `url` variable to `https://011r85m6y8.execute-api.us-east-1.amazonaws.com/dev`
* Once these environments are set up, you can now use Postman to operate the API both locally and as deployed in dev, e.g. `GET {{url}}/people`
* This, obviously, let you switch back and forth between the two environments
* It also solves the problem with Postman following links when the URL has a sub path (e.g. `...amazonaws.com/dev`)
